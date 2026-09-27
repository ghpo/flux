package org.omarchy.flux.net

/** The TCP port range for links. */
val TCP_PORTS = 1716..1764

/** A bidirectional byte stream. */
interface Stream {
    /** Reads up to [length] bytes into [buffer], returning the count or -1 on EOF. */
    fun read(buffer: ByteArray, offset: Int, length: Int): Int

    fun write(bytes: ByteArray)

    fun close()
}

/** A TLS stream whose peer certificate is available for pinning. */
interface ConnectedLink : Stream {
    /** Returns the peer certificate as X.509 DER. */
    fun peerCertificate(): ByteArray
}

/** A TCP server that accepts raw streams. */
interface TcpServer {
    fun localPort(): Int

    /** Accepts the next connection, or returns null when the server is closed. */
    fun accept(): Stream?

    fun close()
}

/** Opens a TCP server on the first free port of [portRange]. */
expect fun openTcpServer(portRange: IntRange): TcpServer?

/** Connects a raw TCP stream to [address]:[port]. */
expect fun tcpConnect(address: String, port: Int): Stream

/**
 * Wraps a connected TCP stream in TLS. When [server] is true this side acts as
 * the TLS server and requires a client certificate. The handshake accepts any
 * certificate; the caller pins it after the fact.
 */
expect fun wrapTls(
    socket: Stream,
    server: Boolean,
    certificate: ByteArray,
    privateKey: ByteArray,
): ConnectedLink
