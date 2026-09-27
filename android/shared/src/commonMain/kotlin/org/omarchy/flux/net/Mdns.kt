package org.omarchy.flux.net

/** A device that mDNS found. */
data class MdnsPeer(
    val deviceId: String,
    val name: String,
    val type: String,
    val ip: String,
    val port: Int,
    val protocol: Int,
)

/**
 * Bonjour/mDNS for KDE Connect links. Each side publishes a
 * `_kdeconnect._udp` service and browses for the services of others. The
 * desktop behind a firewall finds phones only this way, because it dials out.
 */
interface MdnsService {
    /** Publishes this device under [deviceId] with the given TXT attributes. */
    fun publish(deviceId: String, port: Int, txt: Map<String, String>)

    /** Browses for other devices and calls [callback] for each resolved one. */
    fun browse(callback: (MdnsPeer) -> Unit)

    fun stop()
}

expect fun mdnsService(): MdnsService
