package org.omarchy.flux.net

import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.omarchy.flux.protocol.LocalCertificate
import org.omarchy.flux.protocol.Packet
import org.omarchy.flux.protocol.Types
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Runs the TLS handshake over loopback on the actual platform transport, so
 * the same test exercises SSLSocket on the JVM and SecureTransport on iOS.
 */
class TlsLoopbackTest {
    private val phone = LocalCertificate.generate("0123456789abcdef0123456789abcdef")
    private val pc = LocalCertificate.generate("fedcba9876543210fedcba9876543210")

    @Test
    fun tlsRoundTrip() = runBlocking {
        val server = openTcpServer(20000..20100)!!
        val port = server.localPort()

        val serverJob = launch(blockingDispatcher) {
            val socket = server.accept()!!
            val ssl = wrapTls(socket, server = true, phone.certificate, phone.privateKey)
            val got = Packet.parse(readLine(ssl)!!)!!
            assertEquals(1L, got.id)
            ssl.write(Packet(Types.PING, id = 2).serialize().encodeToByteArray())
            ssl.close()
        }

        val client = tcpConnect("127.0.0.1", port)
        val ssl = wrapTls(client, server = false, pc.certificate, pc.privateKey)
        assertContentEquals(phone.certificate, ssl.peerCertificate())
        ssl.write(Packet(Types.PING, id = 1).serialize().encodeToByteArray())
        val reply = Packet.parse(readLine(ssl)!!)!!
        assertEquals(2L, reply.id)
        ssl.close()

        serverJob.join()
        server.close()
    }
}
