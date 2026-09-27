package org.omarchy.flux.net

/** The desktop side runs Avahi in Go, so the JVM shared module has no mDNS. */
private class NoMdns : MdnsService {
    override fun publish(deviceId: String, port: Int, txt: Map<String, String>) = Unit
    override fun browse(callback: (MdnsPeer) -> Unit) = Unit
    override fun stop() = Unit
}

actual fun mdnsService(): MdnsService = NoMdns()
