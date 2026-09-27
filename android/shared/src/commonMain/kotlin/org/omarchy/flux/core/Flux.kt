package org.omarchy.flux.core

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.omarchy.flux.net.DiscoveryListener
import org.omarchy.flux.net.LanBackend
import org.omarchy.flux.net.LanDiscovery
import org.omarchy.flux.net.Link
import org.omarchy.flux.net.MdnsService
import org.omarchy.flux.net.TCP_PORTS
import org.omarchy.flux.net.UDP_PORT
import org.omarchy.flux.net.blockingDispatcher
import org.omarchy.flux.net.lanDiscovery
import org.omarchy.flux.net.mdnsService
import org.omarchy.flux.net.preferred
import org.omarchy.flux.protocol.Identity
import org.omarchy.flux.protocol.LocalCertificate
import org.omarchy.flux.protocol.Packet
import org.omarchy.flux.protocol.Types
import org.omarchy.flux.protocol.bodyOf
import org.omarchy.flux.protocol.currentTimeMillis
import org.omarchy.flux.protocol.subjectPublicKeyInfo
import org.omarchy.flux.protocol.verificationKey
import kotlin.math.abs

const val OUTGOING_TIMEOUT_SECONDS = 30L
const val INCOMING_TIMEOUT_SECONDS = 25L
private const val MAX_TIMESTAMP_DIFFERENCE_SECONDS = 1800L

/**
 * The process-wide state of Flux: the certificate, the paired devices, and
 * the live links. It owns the discovery socket and the LAN backend.
 */
class Flux(private val dir: String, private val deviceName: String) {
    val local: LocalCertificate = LocalCertificate.loadOrCreate(dir)
    val trust: TrustStore = TrustStore(dir)

    private val lock = createLock()
    private val devices = LinkedHashMap<String, Device>()
    private var discovery: LanDiscovery? = null
    private var backend: LanBackend? = null
    private var mdns: MdnsService? = null
    private val scope = CoroutineScope(SupervisorJob() + blockingDispatcher)

    /** Called after every state change, so the UI can refresh its snapshot. */
    var onUpdate: () -> Unit = {}

    /** Receives user-facing messages such as pair requests. */
    var onEvent: (String) -> Unit = {}

    init {
        for (t in trust.all()) {
            val identity = Identity(t.id, t.name, t.type, 8, if (t.isFlux) listOf(Types.FLUX_TUNNEL) else emptyList(), emptyList())
            val d = Device(this, identity)
            d.pairState = PairState.Paired
            d.lastIp = t.lastIp
            d.certificate = runCatching { TrustStore.decodeCert(t.certificate) }.getOrNull()
            devices[t.id] = d
        }
    }

    fun identity(tcpPort: Int): Identity = Identity.self(local.deviceId, deviceName, tcpPort)

    fun start() = start(UDP_PORT, TCP_PORTS)

    fun start(udpPort: Int, tcpPorts: IntRange) {
        if (backend != null) return
        val b = LanBackend(
            localCertificate = local,
            identity = ::identity,
            onLink = { attach(it) },
            trustedCertificate = { id -> trust.get(id)?.let { t -> runCatching { TrustStore.decodeCert(t.certificate) }.getOrNull() } },
            tcpPorts = tcpPorts,
        )
        backend = b
        b.start()
        val port = b.tcpPort
        mdns = mdnsService().also { m ->
            m.publish(
                local.deviceId,
                port,
                mapOf(
                    "id" to local.deviceId,
                    "name" to deviceName,
                    "type" to "phone",
                    "protocol" to "8",
                ),
            )
            m.browse { peer ->
                if (peer.deviceId == local.deviceId || peer.port <= 0) return@browse
                locked {
                    val d = devices.getOrPut(peer.deviceId) { Device(this@Flux, Identity(peer.deviceId, peer.name, peer.type, peer.protocol, emptyList(), emptyList())) }
                    d.lastIp = peer.ip
                }
            }
        }
        discovery = lanDiscovery(object : DiscoveryListener {
            override fun onDatagram(line: String, address: String) {
                val packet = Packet.parse(line) ?: return
                val id = Identity.from(packet) ?: return
                if (id.deviceId == local.deviceId || id.tcpPort <= 0) return
                val online = locked {
                    val d = devices.getOrPut(id.deviceId) { Device(this@Flux, id) }
                    d.identity = id
                    d.lastIp = address
                    d.online
                }
                if (online) return
                b.connect(address, id.tcpPort, id)
            }
        }, udpPort)
        discovery!!.start { identity(port).toPacket(withPort = true).serialize() }
    }

    fun stop() {
        runCatching { discovery?.stop() }
        discovery = null
        runCatching { mdns?.stop() }
        mdns = null
        backend?.stop()
        backend = null
        locked { devices.values.forEach { it.link?.close() } }
    }

    fun snapshot(): List<DeviceUi> = lock.withLock { devices.values.map { it.snapshot() } }

    fun device(id: String): Device? = lock.withLock { devices[id] }

    /** The TCP listener port, or 0 before [start]. */
    fun tcpPort(): Int = backend?.tcpPort ?: 0

    /** Connects to a device at a known address, for example one that mDNS found. */
    fun connectTo(address: String, port: Int) {
        backend?.connect(address, port, null)
    }

    fun <T> locked(block: () -> T): T {
        val r = lock.withLock { block() }
        onUpdate()
        return r
    }

    fun toast(message: String) {
        onEvent(message)
    }

    // ---------------------------------------------------------------- links

    private fun attach(link: Link) {
        locked {
            val id = link.identity.deviceId
            val existing = devices[id]
            val old = existing?.link
            if (old != null && old.isOpen && old !== link) {
                // Each side connected at the same time. Keep the link that
                // the larger device ID opened, like fluxd, so both sides keep
                // the same socket.
                if (preferred(old, link, local.deviceId) === old) {
                    link.close()
                    return@locked
                }
            }
            val d = existing ?: Device(this, link.identity).also { devices[id] = it }
            d.identity = link.identity
            d.link = link
            if (old != null && old !== link) old.close()
            d.certificate = link.peerCertificate
            d.lastIp = ""
            if (trust.get(id) != null) {
                d.pairState = PairState.Paired
                trust.update(id) { it.copy(name = link.identity.deviceName, lastIp = d.lastIp, isFlux = link.identity.isFlux) }
            }
            link.start(onPacket = { p -> locked { dispatch(d, p) } }, onClose = { detach(d, link) })
        }
    }

    private fun detach(d: Device, link: Link) {
        locked {
            if (d.link !== link) return@locked
            d.link = null
            if (d.pairState == PairState.Requested || d.pairState == PairState.Incoming) d.pairState = PairState.None
            if (!d.paired) devices.remove(d.id)
        }
    }

    private fun dispatch(d: Device, p: Packet) {
        if (p.type == Types.PAIR) {
            d.onPairPacket(p)
            return
        }
        // Other packets from unpaired devices are ignored.
    }

    // ---------------------------------------------------------------- actions

    fun pair(id: String, timestamp: Long) = locked { device(id)?.requestPair(timestamp) }
    fun acceptPair(id: String) = locked { device(id)?.acceptPair() }
    fun cancelPair(id: String) = locked { device(id)?.cancelPair() }
    fun unpair(id: String) = locked {
        val d = device(id) ?: return@locked
        d.unpair()
        if (!d.online) devices.remove(id)
    }
}

/** One remote device, holding the pairing state machine. */
class Device(private val core: Flux, var identity: Identity) {
    val id: String get() = identity.deviceId
    var link: Link? = null
    var certificate: ByteArray? = null
    var lastIp: String = ""

    var pairState = PairState.None
    var pairTimestamp = 0L
    var pairKey = ""

    val online: Boolean get() = link?.isOpen == true
    val paired: Boolean get() = pairState == PairState.Paired

    fun send(p: Packet): Boolean {
        if (!paired && p.type != Types.PAIR) return false
        val l = link ?: return false
        if (!l.isOpen) return false
        l.send(p)
        return true
    }

    fun snapshot(): DeviceUi = DeviceUi(
        id = id,
        name = identity.deviceName,
        type = identity.deviceType,
        ip = lastIp,
        isFlux = identity.isFlux,
        paired = paired,
        online = online,
        pairState = pairState,
        pairKey = pairKey,
        pairOutgoing = pairState == PairState.Requested,
    )

    /** The key that a request with [timestamp] would show, before it is sent. */
    fun previewKey(timestamp: Long): String = verificationKeyOf(timestamp)

    fun requestPair(timestamp: Long) {
        if (!online || paired) return
        pairTimestamp = timestamp
        pairState = PairState.Requested
        pairKey = verificationKeyOf(timestamp)
        send(Packet(Types.PAIR, bodyOf("pair" to true, "timestamp" to pairTimestamp)))
    }

    fun acceptPair() {
        if (pairState != PairState.Incoming) return
        send(Packet(Types.PAIR, bodyOf("pair" to true)))
        pairingDone()
    }

    fun cancelPair() {
        if (pairState == PairState.Requested || pairState == PairState.Incoming) {
            send(Packet(Types.PAIR, bodyOf("pair" to false)))
            resetPair()
        }
    }

    fun unpair() {
        send(Packet(Types.PAIR, bodyOf("pair" to false)))
        core.trust.remove(id)
        resetPair()
    }

    fun onPairPacket(p: Packet) {
        val wants = p.bool("pair") ?: false
        if (!wants) {
            val wasPaired = paired
            if (wasPaired) core.trust.remove(id)
            if (pairState == PairState.Requested) core.toast("${identity.deviceName} rejected the pairing")
            else if (wasPaired) core.toast("${identity.deviceName} unpaired this phone")
            resetPair()
            return
        }
        when (pairState) {
            PairState.Requested -> pairingDone()
            PairState.Incoming -> Unit
            PairState.Paired -> {
                core.trust.remove(id)
                pairState = PairState.None
                incoming(p)
            }
            PairState.None -> incoming(p)
        }
    }

    private fun incoming(p: Packet) {
        val ts = p.long("timestamp")
        val now = currentTimeMillis() / 1000
        if (identity.protocolVersion >= 8) {
            if (ts == null || abs(now - ts) > MAX_TIMESTAMP_DIFFERENCE_SECONDS) {
                send(Packet(Types.PAIR, bodyOf("pair" to false)))
                core.toast("Pairing refused: the clock of ${identity.deviceName} is wrong")
                return
            }
        }
        pairTimestamp = ts ?: 0L
        pairKey = verificationKeyOf(pairTimestamp)
        pairState = PairState.Incoming
        core.onEvent("Pair request from ${identity.deviceName}: $pairKey")
    }

    private fun pairingDone() {
        val cert = certificate ?: return
        pairState = PairState.Paired
        core.trust.put(
            TrustedDevice(
                id = id,
                name = identity.deviceName,
                type = identity.deviceType,
                certificate = TrustStore.encodeCert(cert),
                lastIp = lastIp,
                isFlux = identity.isFlux,
            ),
        )
        core.toast("Paired with ${identity.deviceName}")
    }

    private fun resetPair() {
        pairState = PairState.None
        pairKey = ""
    }

    private fun verificationKeyOf(timestamp: Long): String {
        val peer = certificate ?: return ""
        val stamp = if (identity.protocolVersion >= 8) timestamp else 0L
        return verificationKey(
            subjectPublicKeyInfo(core.local.certificate),
            subjectPublicKeyInfo(peer),
            stamp,
        )
    }
}
