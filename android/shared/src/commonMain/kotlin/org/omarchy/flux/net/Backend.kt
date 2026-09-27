package org.omarchy.flux.net

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlin.concurrent.Volatile
import org.omarchy.flux.protocol.Identity
import org.omarchy.flux.protocol.LocalCertificate
import org.omarchy.flux.protocol.Packet
import org.omarchy.flux.protocol.commonName

/**
 * The KDE Connect LAN backend: it accepts TCP links, connects to devices, and
 * runs the TLS handshake plus the identity exchange. [trustedCertificate]
 * returns the pinned certificate of a trusted device, or null when it is not
 * paired yet.
 */
class LanBackend(
    private val localCertificate: LocalCertificate,
    private val identity: (tcpPort: Int) -> Identity,
    private val onLink: (Link) -> Unit,
    private val trustedCertificate: (deviceId: String) -> ByteArray?,
    private val hasLink: (deviceId: String) -> Boolean,
    private val tcpPorts: IntRange = TCP_PORTS,
) {
    var tcpPort = 0
        private set

    private val scope = CoroutineScope(SupervisorJob() + blockingDispatcher)
    @Volatile private var running = false
    private var server: TcpServer? = null

    fun start() {
        if (running) return
        running = true
        server = openTcpServer(tcpPorts)
        tcpPort = server?.localPort() ?: 0
        scope.launch { acceptLoop() }
    }

    fun stop() {
        running = false
        runCatching { server?.close() }
        server = null
    }

    /** Connects to a device, sending the identity first and acting as the TLS server. */
    fun connect(address: String, port: Int, udpIdentity: Identity? = null) {
        scope.launch {
            var socket: Stream? = null
            try {
                socket = tcpConnect(address, port)
                socket.write(identity(0).toPacket(target = udpIdentity).serialize().encodeToByteArray())
                val tls = wrapTls(socket, server = true, localCertificate.certificate, localCertificate.privateKey)
                finish(tls, udpIdentity)
            } catch (e: Exception) {
                runCatching { socket?.close() }
            }
        }
    }

    private suspend fun acceptLoop() {
        while (running) {
            val srv = server ?: return
            val socket = srv.accept() ?: return
            scope.launch { handleIncoming(socket) }
        }
    }

    /** A device opened a TCP connection. This side reads its plain identity and is the TLS client. */
    private suspend fun handleIncoming(socket: Stream) {
        try {
            val line = readLine(socket) ?: throw IllegalStateException("no identity")
            val packet = Packet.parse(line) ?: throw IllegalStateException("bad identity")
            val plain = Identity.from(packet) ?: throw IllegalStateException("bad identity")
            if (plain.deviceId == localCertificate.deviceId) {
                socket.close(); return
            }
            val target = packet.string("targetDeviceId")
            if (target != null && target != localCertificate.deviceId) throw IllegalStateException("identity is for $target")
            val tls = wrapTls(socket, server = false, localCertificate.certificate, localCertificate.privateKey)
            finish(tls, plain)
        } catch (e: Exception) {
            runCatching { socket.close() }
        }
    }

    /**
     * Checks the peer certificate and, for protocol version 8, exchanges the
     * identity again over TLS. The identity inside TLS is the one to trust.
     */
    private fun finish(tls: ConnectedLink, plain: Identity?) {
        val certDer = tls.peerCertificate()
        val cn = commonName(certDer)
        var id = plain
        if (plain == null || plain.protocolVersion >= 8) {
            tls.write(identity(0).toPacket().serialize().encodeToByteArray())
            val line = readLine(tls) ?: throw IllegalStateException("no identity after TLS")
            id = Packet.parse(line)?.let { Identity.from(it) } ?: throw IllegalStateException("bad identity after TLS")
            if (plain != null && plain.deviceId != id.deviceId) throw IllegalStateException("device ID changed after TLS")
            if (plain != null && plain.protocolVersion != id.protocolVersion) throw IllegalStateException("protocol version changed after TLS")
        }
        val deviceId = id.deviceId
        if (cn != deviceId) throw IllegalStateException("certificate CN $cn does not match $deviceId")
        val pinned = trustedCertificate(deviceId)
        if (pinned != null && !pinned.contentEquals(certDer)) {
            throw IllegalStateException("${id.deviceName} presented a different certificate")
        }
        if (hasLink(deviceId)) throw IllegalStateException("already connected to $deviceId")
        onLink(Link(tls, id, certDer))
    }
}
