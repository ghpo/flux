package org.omarchy.flux.net

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DiscoveryTest {
    @Test
    fun receivesLoopbackDatagram() {
        val port = 17301
        val latch = CountDownLatch(1)
        val received = arrayOfNulls<String>(1)
        val discovery = lanDiscovery(object : DiscoveryListener {
            override fun onDatagram(line: String, address: String) {
                // The start() broadcast can loop back on some platforms, so
                // only the datagram we send below counts.
                if (line == "hello-flux") {
                    received[0] = line
                    latch.countDown()
                }
            }
        }, port)
        discovery.start { "identity-line" }
        try {
            DatagramSocket().use { socket ->
                val data = "hello-flux".toByteArray()
                socket.send(DatagramPacket(data, data.size, InetAddress.getByName("127.0.0.1"), port))
            }
            assertTrue("no datagram arrived", latch.await(5, TimeUnit.SECONDS))
            assertEquals("hello-flux", received[0])
        } finally {
            discovery.stop()
        }
    }
}
