package org.omarchy.flux.protocol

import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Calendar
import java.util.UUID
import javax.security.auth.x500.X500Principal

actual object localCertificateStore {
    private const val KEY_FILE = "privateKey.der"
    private const val CERT_FILE = "certificate.der"

    actual fun loadOrCreate(dir: String): LocalCertificate {
        val d = File(dir)
        val keyFile = File(d, KEY_FILE)
        val certFile = File(d, CERT_FILE)
        if (keyFile.exists() && certFile.exists()) {
            runCatching {
                KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(keyFile.readBytes()))
                parseCertificate(certFile.readBytes())
                return LocalCertificate(keyFile.readBytes(), certFile.readBytes())
            }
        }
        val created = generate(UUID.randomUUID().toString().replace("-", ""))
        d.mkdirs()
        keyFile.writeBytes(created.privateKey)
        certFile.writeBytes(created.certificate)
        return created
    }

    actual fun generate(deviceId: String): LocalCertificate {
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val name = X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, deviceId)
            .addRDN(BCStyle.OU, "KDE Connect")
            .addRDN(BCStyle.O, "KDE")
            .build()
        val now = Calendar.getInstance()
        val notBefore = (now.clone() as Calendar).apply { add(Calendar.YEAR, -1) }.time
        val notAfter = (now.clone() as Calendar).apply { add(Calendar.YEAR, 10) }.time
        val builder = JcaX509v3CertificateBuilder(name, BigInteger.ONE, notBefore, notAfter, name, pair.public)
            .addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        val signer = JcaContentSignerBuilder("SHA256WithRSA").build(pair.private)
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(signer))
        return LocalCertificate(pair.private.encoded, cert.encoded)
    }

    actual fun parseCertificate(der: ByteArray): CertificateInfo {
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
        val dn = cert.subjectX500Principal.getName(X500Principal.RFC2253)
        val spki = org.bouncycastle.asn1.x509.Certificate.getInstance(der).subjectPublicKeyInfo.encoded
        return CertificateInfo(dn, spki)
    }
}
