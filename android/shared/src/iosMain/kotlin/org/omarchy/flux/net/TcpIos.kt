package org.omarchy.flux.net

/**
 * The iOS TCP and TLS transport is not implemented yet.
 *
 * The real implementation will use NWConnection and NWListener with a
 * SecIdentity (certificate plus the RSA key in the keychain) and a
 * sec_protocol_options verify block that accepts any certificate so the link
 * can pin it after the handshake, matching the JVM backend in TcpJvm.kt.
 */
actual fun openTcpServer(portRange: IntRange): TcpServer? =
    throw NotImplementedError("iOS TCP server is not implemented yet")

actual fun tcpConnect(address: String, port: Int): Stream =
    throw NotImplementedError("iOS TCP connect is not implemented yet")

actual fun wrapTls(
    socket: Stream,
    server: Boolean,
    certificate: ByteArray,
    privateKey: ByteArray,
): ConnectedLink = throw NotImplementedError("iOS TLS is not implemented yet")
