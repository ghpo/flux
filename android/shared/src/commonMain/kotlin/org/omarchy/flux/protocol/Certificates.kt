package org.omarchy.flux.protocol

/**
 * The device identity: its RSA private key as PKCS#8 DER and its self-signed
 * certificate as X.509 DER. The common code holds only the bytes so that the
 * JVM and iOS implementations can use their own crypto backends.
 */
class LocalCertificate(
    val privateKey: ByteArray,
    val certificate: ByteArray,
) {
    /** The device ID is the common name of the certificate. */
    val deviceId: String get() = commonName(certificate) ?: error("certificate has no CN")

    companion object {
        /** Loads the certificate from [dir], generating a new one on first use. */
        fun loadOrCreate(dir: String): LocalCertificate = localCertificateStore.loadOrCreate(dir)

        /** Generates a self-signed certificate in the KDE Connect format. */
        fun generate(deviceId: String): LocalCertificate = localCertificateStore.generate(deviceId)
    }
}

/** A parsed certificate: its RFC 2253 subject and its SubjectPublicKeyInfo DER. */
class CertificateInfo(val subjectRfc2253: String?, val subjectPublicKeyInfo: ByteArray)

/** Platform certificate operations: key generation, persistence, and parsing. */
expect object localCertificateStore {
    fun loadOrCreate(dir: String): LocalCertificate
    fun generate(deviceId: String): LocalCertificate
    fun parseCertificate(der: ByteArray): CertificateInfo
}

/** Returns the SHA-256 digest of [data]. */
expect fun sha256(data: ByteArray): ByteArray

/** Returns the CN of the certificate subject. */
fun commonName(certificateDer: ByteArray): String? {
    val dn = localCertificateStore.parseCertificate(certificateDer).subjectRfc2253 ?: return null
    return dn.split(',').map { it.trim() }.firstOrNull { it.startsWith("CN=") }?.removePrefix("CN=")
}

/** Returns the SubjectPublicKeyInfo DER bytes exactly as the certificate holds them. */
fun subjectPublicKeyInfo(certificateDer: ByteArray): ByteArray =
    localCertificateStore.parseCertificate(certificateDer).subjectPublicKeyInfo

/**
 * Returns the 8-character key that both devices show while they pair. It
 * hashes the 2 public keys, larger first, then the pairing timestamp in
 * seconds as decimal text.
 */
fun verificationKey(own: ByteArray, peer: ByteArray, timestamp: Long): String {
    var a = own
    var b = peer
    if (compareBytes(a, b) < 0) {
        val t = a; a = b; b = t
    }
    val md = sha256(a + b + if (timestamp > 0) timestamp.toString().encodeToByteArray() else ByteArray(0))
    return md.toHex().substring(0, 8).uppercase()
}

/** Compares bytes as unsigned values, the same way Go bytes.Compare does. */
fun compareBytes(a: ByteArray, b: ByteArray): Int {
    val n = minOf(a.size, b.size)
    for (i in 0 until n) {
        val x = a[i].toInt() and 0xff
        val y = b[i].toInt() and 0xff
        if (x != y) return x - y
    }
    return a.size - b.size
}

private val hexChars = "0123456789abcdef".toCharArray()

/** Returns the lowercase hexadecimal form of this byte array. */
fun ByteArray.toHex(): String = buildString(capacity = size * 2) {
    for (b in this@toHex) {
        append(hexChars[(b.toInt() shr 4) and 0x0f])
        append(hexChars[b.toInt() and 0x0f])
    }
}
