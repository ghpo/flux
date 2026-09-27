package org.omarchy.flux.net

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlin.concurrent.Volatile
import org.omarchy.flux.protocol.Identity
import org.omarchy.flux.protocol.Packet
import org.omarchy.flux.protocol.currentTimeMillis

/** The largest packet line that Flux reads. */
const val MAX_LINE = 16 * 1024 * 1024

/**
 * The time in which a second link to the same device counts as a
 * simultaneous connection and not as a reconnect.
 */
const val RACE_WINDOW_MS = 5_000L

/**
 * An open TLS link to one device. It frames the newline-separated packets
 * over [transport] and runs the reader on a background coroutine.
 */
class Link(
    private val transport: ConnectedLink,
    val identity: Identity,
    val peerCertificate: ByteArray,
    val outgoing: Boolean,
    val startedAt: Long = currentTimeMillis(),
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
        runCatching { transport.write(packet.serialize().encodeToByteArray()) }
    }

    val isOpen: Boolean get() = !closed

    fun close() {
        if (closed) return
        closed = true
        runCatching { transport.close() }
    }
}

/**
 * Picks the link to keep when two links to the same device exist at the same
 * time. Each side keeps the link that the device with the larger ID opened,
 * so both sides keep the same socket. After the race window, the new link
 * wins, because the old socket can be dead without an error.
 */
fun preferred(old: Link, next: Link, selfId: String): Link {
    if (currentTimeMillis() - old.startedAt > RACE_WINDOW_MS) return next
    val opener = { l: Link -> if (l.outgoing) selfId else l.identity.deviceId }
    val larger = maxOf(selfId, next.identity.deviceId)
    return if (opener(old) == larger && opener(next) != larger) old else next
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
