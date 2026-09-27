package org.omarchy.flux.net

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlin.concurrent.Volatile
import org.omarchy.flux.protocol.Identity
import org.omarchy.flux.protocol.Packet

/** The largest packet line that Flux reads. */
const val MAX_LINE = 16 * 1024 * 1024

/**
 * An open TLS link to one device. It frames the newline-separated packets
 * over [transport] and runs the reader on a background coroutine.
 */
class Link(
    private val transport: ConnectedLink,
    val identity: Identity,
    val peerCertificate: ByteArray,
) {
    private val scope = CoroutineScope(SupervisorJob() + blockingDispatcher)
    @Volatile private var closed = false

    /** Starts the read loop. [onPacket] runs on the reader coroutine. */
    fun start(onPacket: (Packet) -> Unit, onClose: () -> Unit) {
        scope.launch {
            try {
                while (!closed) {
                    val line = readLine(transport) ?: break
                    if (line.isBlank()) continue
                    val p = Packet.parse(line) ?: continue
                    runCatching { onPacket(p) }
                }
            } finally {
                close()
                onClose()
            }
        }
    }

    fun send(packet: Packet) {
        if (closed) return
        runCatching { transport.write(packet.serialize().toByteArray()) }
    }

    fun close() {
        if (closed) return
        closed = true
        runCatching { transport.close() }
    }
}

/**
 * Reads one line from the stream, 1 byte at a time. On a raw socket before
 * TLS, this does not consume the bytes of the TLS handshake.
 */
fun readLine(stream: Stream, max: Int = MAX_LINE): String? {
    var buf = ByteArray(256)
    var size = 0
    val one = ByteArray(1)
    while (true) {
        val n = stream.read(one, 0, 1)
        if (n < 0) return if (size == 0) null else buf.copyOf(size).decodeToString()
        if (n == 0) continue
        val b = one[0]
        if (b == '\n'.code.toByte()) return buf.copyOf(size).decodeToString()
        if (size == buf.size) buf = buf.copyOf(buf.size * 2)
        buf[size++] = b
        if (size > max) error("packet too large")
    }
}
