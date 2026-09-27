package org.omarchy.flux.net

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.SocketException
import java.util.concurrent.Executors

private class JvmLanDiscovery(private val listener: DiscoveryListener, private val port: Int) : LanDiscovery {
    private val pool = Executors.newCachedThreadPool { Thread(it, "flux-lan").apply { isDaemon = true } }
    @Volatile private var running = false
    private var udp: DatagramSocket? = null

    override fun start(identityLine: () -> String) {
        if (running) return
        running = true
        udp = openUdp()
        pool.execute { udpLoop() }
        broadcast(identityLine())
    }

    override fun announce(line: String, address: String) {
        if (!running) return
        pool.execute {
            val data = line.toByteArray()
            runCatching { udp?.send(DatagramPacket(data, data.size, InetAddress.getByName(address), port)) }
        }
    }

    override fun broadcast(line: String) {
        if (!running) return
        pool.execute {
            val data = line.toByteArray()
            for (target in broadcastTargets()) {
                runCatching { udp?.send(DatagramPacket(data, data.size, target, port)) }
            }
        }
    }

    override fun stop() {
        running = false
        runCatching { udp?.close() }
        udp = null
    }

    private fun openUdp(): DatagramSocket? = runCatching {
        val socket = DatagramSocket(null)
        socket.reuseAddress = true
        socket.broadcast = true
        socket.bind(InetSocketAddress(port))
        socket
    }.getOrNull()

    private fun broadcastTargets(): List<InetAddress> {
        val targets = LinkedHashSet<InetAddress>()
        targets += InetAddress.getByName("255.255.255.255")
        runCatching {
            NetworkInterface.getNetworkInterfaces().toList()
                .filter { it.isUp && !it.isLoopback }
                .flatMap { it.interfaceAddresses }
                .filter { it.address is Inet4Address }
                .mapNotNull { it.broadcast }
                .forEach { targets += it }
        }
        return targets.toList()
    }

    private fun udpLoop() {
        val buf = ByteArray(64 * 1024)
        while (running) {
            val socket = udp ?: return
            val dp = DatagramPacket(buf, buf.size)
            try {
                socket.receive(dp)
            } catch (e: SocketException) {
                // A transient error, for example ICMP port-unreachable after a
                // broadcast. Keep listening.
                if (!running) return
                continue
            } catch (e: Exception) {
                return
            }
            val line = String(dp.data, dp.offset, dp.length, Charsets.UTF_8)
            listener.onDatagram(line, dp.address.hostAddress ?: "")
        }
    }
}

actual fun lanDiscovery(listener: DiscoveryListener, port: Int): LanDiscovery = JvmLanDiscovery(listener, port)
