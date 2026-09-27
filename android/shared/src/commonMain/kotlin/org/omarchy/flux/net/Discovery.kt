package org.omarchy.flux.net

/** The UDP port for identity broadcasts. */
const val UDP_PORT = 1716

/** Receives raw identity lines that arrive over UDP. */
interface DiscoveryListener {
    /** A datagram arrived from [address]. */
    fun onDatagram(line: String, address: String)
}

/**
 * UDP broadcast discovery for KDE Connect links. Each side announces its
 * identity and listens for the identities of others. The transport details
 * differ by platform.
 */
interface LanDiscovery {
    /** Starts listening and announces [identityLine] to the broadcast addresses. */
    fun start(identityLine: () -> String)

    /** Sends [line] to one address. */
    fun announce(line: String, address: String)

    /** Sends [line] to every broadcast address. */
    fun broadcast(line: String)

    fun stop()
}

expect fun lanDiscovery(listener: DiscoveryListener, port: Int = UDP_PORT): LanDiscovery
