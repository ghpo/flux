package org.omarchy.flux.net

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.omarchy.flux.protocol.Identity
import org.omarchy.flux.protocol.LocalCertificate
import org.omarchy.flux.protocol.Packet
import org.omarchy.flux.protocol.Types

class LinkTest {
    private val phone = LocalCertificate.generate("0123456789abcdef0123456789abcdef")
    private val pc = LocalCertificate.generate("fedcba9876543210fedcba9876543210")

    @Test
    fun tlsRoundTrip() {
        val server = openTcpServer(20000..20100)!!
        val port = server.localPort()

        val serverReceived = CountDownLatch(1)
        val serverThread = thread {
            val socket = server.accept()!!
            val ssl = wrapTls(socket, server = true, phone.certificate, phone.privateKey)
            val got = Packet.parse(readLine(ssl)!!)!!
            assertEquals(1L, got.id)
            ssl.write(Packet(Types.PING, id = 2).serialize().toByteArray())
            serverReceived.countDown()
            ssl.close()
        }

        val client = tcpConnect("127.0.0.1", port)
        val ssl = wrapTls(client, server = false, pc.certificate, pc.privateKey)
        assertArrayEquals(phone.certificate, ssl.peerCertificate())
        ssl.write(Packet(Types.PING, id = 1).serialize().toByteArray())
        val reply = Packet.parse(readLine(ssl)!!)!!
        assertEquals(2L, reply.id)
        ssl.close()

        assertTrue("server did not finish the exchange", serverReceived.await(5, TimeUnit.SECONDS))
        serverThread.join(5000)
        server.close()
    }

    @Test
    fun backendExchangesIdentityOverTls() {
        val phoneLinks = CopyOnWriteArrayList<Link>()
        val pcLinks = CopyOnWriteArrayList<Link>()

        val phoneBackend = LanBackend(
            localCertificate = phone,
            identity = { port -> Identity.self(phone.deviceId, "iPhone", port) },
            onLink = { phoneLinks.add(it) },
            trustedCertificate = { null },
            hasLink = { false },
        )
        val pcBackend = LanBackend(
            localCertificate = pc,
            identity = { port -> Identity.self(pc.deviceId, "PC", port) },
            onLink = { pcLinks.add(it) },
            trustedCertificate = { null },
            hasLink = { false },
        )

        phoneBackend.start()
        pcBackend.start()
        try {
            phoneBackend.connect("127.0.0.1", pcBackend.tcpPort, null)

            val deadline = System.currentTimeMillis() + 5000
            while ((phoneLinks.isEmpty() || pcLinks.isEmpty()) && System.currentTimeMillis() < deadline) {
                Thread.sleep(20)
            }

            assertEquals(1, phoneLinks.size)
            assertEquals(1, pcLinks.size)
            val phoneSide = phoneLinks.first()
            val pcSide = pcLinks.first()
            assertEquals(pc.deviceId, phoneSide.identity.deviceId)
            assertEquals(phone.deviceId, pcSide.identity.deviceId)
            assertArrayEquals(pc.certificate, phoneSide.peerCertificate)
            assertArrayEquals(phone.certificate, pcSide.peerCertificate)
            assertNotNull(Packet.parse(phoneSide.identity.toPacket().serialize()))
        } finally {
            phoneBackend.stop()
            pcBackend.stop()
        }
    }
}
