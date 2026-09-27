package org.omarchy.flux.protocol

import java.io.File
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.util.UUID

private const val KEY_FILE = "privateKey.der"
private const val CERT_FILE = "certificate.der"

actual fun generateRsaKeyPair(bits: Int): RsaKeyPair {
    val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()
    return RsaKeyPair(pair.public.encoded, pair.private.encoded)
}

actual fun rsaSignSha256(privateKeyPkcs8: ByteArray, message: ByteArray): ByteArray {
    val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKeyPkcs8))
    val sig = Signature.getInstance("SHA256withRSA")
    sig.initSign(key)
    sig.update(message)
    return sig.sign()
}

actual fun loadOrCreateCertificate(dir: String): LocalCertificate {
    val d = File(dir)
    val keyFile = File(d, KEY_FILE)
    val certFile = File(d, CERT_FILE)
    if (keyFile.exists() && certFile.exists()) {
        runCatching {
            parseCertificate(certFile.readBytes())
            return LocalCertificate(keyFile.readBytes(), certFile.readBytes())
        }
    }
    val created = generateCertificate(UUID.randomUUID().toString().replace("-", ""))
    d.mkdirs()
    keyFile.writeBytes(created.privateKey)
    certFile.writeBytes(created.certificate)
    return created
}
