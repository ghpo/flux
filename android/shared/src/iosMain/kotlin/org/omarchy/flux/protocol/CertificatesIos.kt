package org.omarchy.flux.protocol

/**
 * iOS certificate backend.
 *
 * Not implemented yet. The real implementation will use the Security
 * framework: `SecKeyCreateRandomKey` for an RSA 2048 key,
 * `SecKeyCreateCertificate` for the self-signed certificate, and
 * `SecCertificateCopyData` for its DER. Parsing will extract the subject and
 * the SubjectPublicKeyInfo from that DER.
 *
 * It is stubbed so that the shared module compiles for iOS while the JVM
 * implementation is verified. See CertificatesJvm.kt for the reference
 * behavior.
 */
actual object localCertificateStore {
    actual fun loadOrCreate(dir: String): LocalCertificate =
        throw NotImplementedError("iOS certificate store is not implemented yet")

    actual fun generate(deviceId: String): LocalCertificate =
        throw NotImplementedError("iOS certificate store is not implemented yet")

    actual fun parseCertificate(der: ByteArray): CertificateInfo =
        throw NotImplementedError("iOS certificate store is not implemented yet")
}
