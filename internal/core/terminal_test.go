package core

import (
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestParsePtyRequest(t *testing.T) {
	payload := append([]byte{0, 0, 0, 5, 'x', 't', 'e', 'r', 'm'}, 0, 0, 0, 100, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0)
	term, cols, rows := parsePtyRequest(payload)
	if term != "xterm" || cols != 100 || rows != 40 {
		t.Fatalf("got %q %d %d, want xterm 100 40", term, cols, rows)
	}
}

func TestParseWindowChange(t *testing.T) {
	payload := []byte{0, 0, 0, 120, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0}
	cols, rows := parseWindowChange(payload)
	if cols != 120 || rows != 50 {
		t.Fatalf("got %d %d, want 120 50", cols, rows)
	}
}

func TestTerminalSession(t *testing.T) {
	name := "flux-test-" + time.Now().Format("150405")
	defer func() { _ = exec.Command("tmux", "kill-session", "-t", name).Run() }()

	cfg, password, err := browseConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		serveTerminal(conn, cfg, name, func(string, ...any) {})
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, chans, reqs, err := ssh.NewClientConn(client, "test", &ssh.ClientConfig{
		User:            "kdeconnect",
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	sshClient := ssh.NewClient(conn, chans, reqs)
	defer sshClient.Close()

	session, err := sshClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}

	// Give tmux and the shell time to start before sending the command.
	time.Sleep(500 * time.Millisecond)

	marker := "flux-terminal-ok"
	if _, err := stdin.Write([]byte("echo " + marker + "\n")); err != nil {
		t.Fatal(err)
	}

	outCh := make(chan string, 1)
	go func() {
		var out strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
			}
			if strings.Contains(out.String(), marker) || err != nil {
				outCh <- out.String()
				return
			}
		}
	}()

	select {
	case out := <-outCh:
		if !strings.Contains(out, marker) {
			t.Fatalf("no %q in output: %q", marker, out)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for the terminal output")
	}
}
