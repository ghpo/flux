package org.omarchy.flux.protocol

/**
 * Self-signed RSA certificate construction and parsing, plus the PKCS#8 and
 * SubjectPublicKeyInfo wrappers that the platform crypto backends need.
 */

private const val OID_CN = "2.5.4.3"
private const val OID_OU = "2.5.4.11"
private const val OID_O = "2.5.4.10"
private const val OID_RSA = "1.2.840.113549.1.1.1"
private const val OID_SHA256_RSA = "1.2.840.113549.1.1.11"

private val CN_OID = byteArrayOf(0x55, 0x04, 0x03)
private val OU_OID = byteArrayOf(0x55, 0x04, 0x0b)
private val O_OID = byteArrayOf(0x55, 0x04, 0x0a)

internal fun rsaAlgorithmIdentifier(): ByteArray = derSequence(derOid(OID_RSA), derNull())

internal fun sha256RsaAlgorithmIdentifier(): ByteArray = derSequence(derOid(OID_SHA256_RSA), derNull())

/** Builds a self-signed X.509 v3 certificate with CN set to [deviceId]. */
internal fun buildSelfSignedRsaCertificate(
    deviceId: String,
    publicKeySpki: ByteArray,
    sign: (ByteArray) -> ByteArray,
): ByteArray {
    val cn = derSet(derSequence(derOid(OID_CN), derUtf8String(deviceId)))
    val ou = derSet(derSequence(derOid(OID_OU), derUtf8String("KDE Connect")))
    val o = derSet(derSequence(derOid(OID_O), derUtf8String("KDE")))
    val name = derSequence(cn, ou, o)

    val now = currentTimeMillis()
    val validity = derSequence(
        derUtcTime(now - 365L * 24 * 3600 * 1000),
        derUtcTime(now + 10L * 365 * 24 * 3600 * 1000),
    )

    val sigAlg = sha256RsaAlgorithmIdentifier()
    val tbs = derSequence(derExplicit(0, derInteger(2L)), derInteger(1L), sigAlg, name, validity, name, publicKeySpki)
    val signature = sign(tbs)
    return derSequence(tbs, sigAlg, derBitString(signature))
}

/** Wraps a PKCS#1 RSAPublicKey into a SubjectPublicKeyInfo. */
internal fun wrapRsaSpki(pkcs1: ByteArray): ByteArray =
    derSequence(rsaAlgorithmIdentifier(), derBitString(pkcs1))

/** Wraps a PKCS#1 RSAPrivateKey into a PKCS#8 PrivateKeyInfo. */
internal fun wrapPkcs8(pkcs1: ByteArray): ByteArray =
    derSequence(derInteger(0L), rsaAlgorithmIdentifier(), derOctetString(pkcs1))

/** Returns the PKCS#1 RSAPrivateKey held inside a PKCS#8 PrivateKeyInfo. */
internal fun unwrapPkcs8(pkcs8: ByteArray): ByteArray {
    val outer = readDerTlv(pkcs8, 0)
    val kids = derChildren(pkcs8, outer)
    return derContent(pkcs8, kids[2])
}

/** Returns the PKCS#1 RSAPublicKey held inside a SubjectPublicKeyInfo. */
internal fun unwrapSpki(spki: ByteArray): ByteArray {
    val outer = readDerTlv(spki, 0)
    val kids = derChildren(spki, outer)
    val bitString = kids[1]
    return spki.copyOfRange(bitString.content + 1, bitString.contentEnd)
}

/** Parses an X.509 certificate into its subject and SubjectPublicKeyInfo. */
fun parseCertificate(der: ByteArray): CertificateInfo {
    val cert = readDerTlv(der, 0)
    val certKids = derChildren(der, cert)
    val tbs = certKids[0]
    val tbsKids = derChildren(der, tbs)
    val base = if (tbsKids[0].tag == 0xA0) 1 else 0
    val subject = tbsKids[base + 4]
    val spki = tbsKids[base + 5]
    return CertificateInfo(subjectDn(der, subject), derRaw(der, spki))
}

private fun subjectDn(bytes: ByteArray, name: DerTlv): String? {
    val parts = ArrayList<String>()
    for (rdn in derChildren(bytes, name)) {
        val atvs = derChildren(bytes, rdn)
        if (atvs.isEmpty()) continue
        val atvKids = derChildren(bytes, atvs[0])
        if (atvKids.size < 2) continue
        val label = when {
            derContent(bytes, atvKids[0]).contentEquals(CN_OID) -> "CN"
            derContent(bytes, atvKids[0]).contentEquals(OU_OID) -> "OU"
            derContent(bytes, atvKids[0]).contentEquals(O_OID) -> "O"
            else -> null
        } ?: continue
        val value = stringValue(bytes, atvKids[1]) ?: continue
        parts.add("$label=$value")
    }
    return if (parts.isEmpty()) null else parts.joinToString(",")
}

private fun stringValue(bytes: ByteArray, tlv: DerTlv): String? = when (tlv.tag) {
    0x0c, 0x13, 0x16 -> derContent(bytes, tlv).decodeToString()
    else -> null
}

// ----- Civil time for the UTCTime validity window -----

internal fun daysFromCivil(year: Int, month: Int, day: Int): Long {
    val y = if (month <= 2) year - 1 else year
    val era = (if (y >= 0) y else y - 399) / 400
    val yoe = y - era * 400
    val m = if (month > 2) month - 3 else month + 9
    val doy = (153 * m + 2) / 5 + day - 1
    val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
    return era.toLong() * 146097 + doe - 719468
}

internal fun civilFromDays(z0: Long): Triple<Int, Int, Int> {
    val z = z0 + 719468
    val era = if (z >= 0) z / 146097 else (z - 146096) / 146097
    val doe = z - era * 146097
    val yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
    val y = yoe + era * 400
    val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
    val mp = (5 * doy + 2) / 153
    val d = doy - (153 * mp + 2) / 5 + 1
    val m = if (mp < 10) mp + 3 else mp - 9
    return Triple((y + (if (m <= 2) 1 else 0)).toInt(), m.toInt(), d.toInt())
}

internal fun utcTimeString(millis: Long): String {
    val totalSeconds = millis / 1000
    val days = totalSeconds / 86400
    val secOfDay = (totalSeconds % 86400).toInt()
    val (year, month, day) = civilFromDays(days)
    val hh = secOfDay / 3600
    val mm = (secOfDay % 3600) / 60
    val ss = secOfDay % 60
    val yy = ((year % 100 + 100) % 100).toString().padStart(2, '0')
    return yy + month.toString().padStart(2, '0') + day.toString().padStart(2, '0') +
        hh.toString().padStart(2, '0') + mm.toString().padStart(2, '0') + ss.toString().padStart(2, '0') + "Z"
}
