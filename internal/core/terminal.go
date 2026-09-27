package core

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"

	"flux/internal/lan"
	"flux/internal/proto"
)

// maxTerminalSession is the longest time that one terminal tunnel stays
// open. The tmux session itself keeps running on the desktop; this only
// limits one attach from the phone.
const maxTerminalSession = 24 * time.Hour

// handleTerminalRequest answers flux.terminal.request from a Flux phone.
// The SSH server does not listen on the network: the phone opens a tunnel
// listener, fluxd connects out to it, and the tmux session runs inside the
// tunnel, so it works with a firewall that blocks incoming traffic.
func (d *Daemon) handleTerminalRequest(dev *Device, l *lan.Link, p *proto.Packet) {
	var b struct {
		Start bool `json:"start"`
	}
	if p.Decode(&b) != nil || !b.Start {
		return
	}
	d.mu.Lock()
	allowed := d.cfg.AllowTerminal
	session := d.cfg.TerminalSession
	d.mu.Unlock()
	if !allowed {
		_ = l.Send(proto.New(proto.TypeFluxTerminal, map[string]any{
			"errorMessage": "Terminal is off on this computer. Set allow_terminal = true in ~/.config/flux/config.toml",
		}))
		return
	}
	if !l.CanTunnel() {
		_ = l.Send(proto.New(proto.TypeFluxTerminal, map[string]any{"errorMessage": "Terminal needs Flux for Android"}))
		return
	}
	if session == "" {
		session = "flux"
	}
	if _, err := exec.LookPath("tmux"); err != nil {
		_ = l.Send(proto.New(proto.TypeFluxTerminal, map[string]any{"errorMessage": "tmux is not installed on this computer"}))
		return
	}
	cfg, password, err := browseConfig()
	if err != nil {
		_ = l.Send(proto.New(proto.TypeFluxTerminal, map[string]any{"errorMessage": err.Error()}))
		return
	}
	id := l.NewTunnelID()
	if err := l.Send(proto.New(proto.TypeFluxTerminal, map[string]any{
		"tunnel": id, "user": "kdeconnect", "password": password, "session": session,
	})); err != nil {
		l.TunnelReady(id, 0, "canceled")
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(d.ctx, maxTerminalSession)
		defer cancel()
		tc, err := l.OpenTunnel(ctx, id)
		if err != nil {
			d.logf("%s: terminal tunnel: %v", dev.Name, err)
			return
		}
		stop := context.AfterFunc(ctx, func() { tc.Close() })
		defer stop()
		d.toast("%s opened a terminal", dev.Name)
		serveTerminal(tc, cfg, session, d.logf)
	}()
}

// serveTerminal runs an SSH server on one connection that serves the shared
// tmux session until the client closes it.
func serveTerminal(conn net.Conn, cfg *ssh.ServerConfig, session string, logf func(string, ...any)) {
	defer conn.Close()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		logf("terminal SSH: %v", err)
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, requests, err := nc.Accept()
		if err != nil {
			continue
		}
		go serveTerminalSession(ch, requests, session, logf)
	}
}

// serveTerminalSession handles the requests of one session channel. It
// allocates a pseudo-terminal and runs tmux in it, wiring the channel to the
// tmux process. When the client detaches, the tmux session stays on the
// desktop, so a later attach continues the same session.
func serveTerminalSession(ch ssh.Channel, requests <-chan *ssh.Request, session string, logf func(string, ...any)) {
	defer ch.Close()

	var (
		ptmx *os.File
		tty  *os.File
		cmd  *exec.Cmd
	)
	term := "xterm-256color"

	for req := range requests {
		switch req.Type {
		case "pty-req":
			if t, cols, rows := parsePtyRequest(req.Payload); t != "" {
				term = t
				if cols > 0 && rows > 0 {
					// The size is applied after the pty opens, below.
				}
			}
			master, slave, err := pty.Open()
			if err != nil {
				logf("terminal pty: %v", err)
				_ = req.Reply(false, nil)
				continue
			}
			ptmx, tty = master, slave
			if _, cols, rows := parsePtyRequest(req.Payload); cols > 0 && rows > 0 {
				_ = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
			}
			_ = req.Reply(true, nil)

		case "shell":
			if ptmx == nil {
				_ = req.Reply(false, nil)
				continue
			}
			cmd = exec.Command("tmux", "new-session", "-A", "-s", session)
			cmd.Env = append(os.Environ(), "TERM="+term)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
			if err := cmd.Start(); err != nil {
				logf("terminal tmux: %v", err)
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			go func() {
				_, _ = io.Copy(ptmx, ch)
				_ = ptmx.Close()
			}()
			_, _ = io.Copy(ch, ptmx)
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}

		case "window-change":
			if ptmx == nil {
				continue
			}
			cols, rows := parseWindowChange(req.Payload)
			if cols > 0 && rows > 0 {
				_ = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
			}

		default:
			_ = req.Reply(false, nil)
		}
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	if tty != nil {
		_ = tty.Close()
	}
	if ptmx != nil {
		_ = ptmx.Close()
	}
}

// parsePtyRequest reads the term, columns, and rows from a pty-req payload.
func parsePtyRequest(payload []byte) (term string, cols, rows int) {
	if len(payload) < 4 {
		return "", 0, 0
	}
	n := int(binary.BigEndian.Uint32(payload[:4]))
	payload = payload[4:]
	if n < 0 || n > len(payload) {
		return "", 0, 0
	}
	term = string(payload[:n])
	payload = payload[n:]
	if len(payload) < 8 {
		return term, 0, 0
	}
	cols = int(binary.BigEndian.Uint32(payload[0:4]))
	rows = int(binary.BigEndian.Uint32(payload[4:8]))
	return term, cols, rows
}

// parseWindowChange reads the columns and rows from a window-change payload.
func parseWindowChange(payload []byte) (cols, rows int) {
	if len(payload) < 8 {
		return 0, 0
	}
	cols = int(binary.BigEndian.Uint32(payload[0:4]))
	rows = int(binary.BigEndian.Uint32(payload[4:8]))
	return cols, rows
}
