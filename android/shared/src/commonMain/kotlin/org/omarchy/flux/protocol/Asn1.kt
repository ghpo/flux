package org.omarchy.flux.protocol

/**
 * A minimal DER encoder and reader for the X.509 fields that Flux needs.
 * It is intentionally small: it builds and parses self-signed certificates
 * and the RSA key wrappers, and nothing else.
 */

// ----- Writing -----

internal fun derLength(len: Int): ByteArray = when {
    len < 0x80 -> byteArrayOf(len.toByte())
    len < 0x100 -> byteArrayOf(0x81.toByte(), len.toByte())
    len < 0x10000 -> byteArrayOf(0x82.toByte(), (len shr 8).toByte(), len.toByte())
    else -> byteArrayOf(0x84.toByte(), (len shr 24).toByte(), (len shr 16).toByte(), (len shr 8).toByte(), len.toByte())
}

internal fun derTlv(tag: Int, content: ByteArray): ByteArray =
    byteArrayOf(tag.toByte()) + derLength(content.size) + content

internal fun derSequence(vararg children: ByteArray): ByteArray =
    derTlv(0x30, children.fold(ByteArray(0)) { acc, c -> acc + c })

internal fun derSet(vararg children: ByteArray): ByteArray =
    derTlv(0x31, children.fold(ByteArray(0)) { acc, c -> acc + c })

internal fun derInteger(value: Long): ByteArray {
    require(value >= 0) { "only non-negative integers are encoded" }
    var len = 1
    var tmp = value
    while (tmp > 0x7f) { len++; tmp = tmp shr 8 }
    val bytes = ByteArray(len)
    var v = value
    for (i in len - 1 downTo 0) {
        bytes[i] = (v and 0xff).toByte()
        v = v shr 8
    }
    return if (bytes[0].toInt() and 0x80 != 0) {
        derTlv(0x02, byteArrayOf(0) + bytes)
    } else {
        derTlv(0x02, bytes)
    }
}

internal fun derOid(oid: String): ByteArray {
    val arcs = oid.split('.').map { it.toInt() }
    require(arcs.size >= 2 && arcs[0] in 0..2 && arcs[1] < 40) { "unsupported OID: $oid" }
    val out = ArrayList<Byte>()
    out.add((arcs[0] * 40 + arcs[1]).toByte())
    for (i in 2 until arcs.size) {
        var arc = arcs[i]
        val stack = ArrayList<Byte>()
        stack.add((arc and 0x7f).toByte())
        arc = arc shr 7
        while (arc > 0) {
            stack.add((0x80 or (arc and 0x7f)).toByte())
            arc = arc shr 7
        }
        for (b in stack.asReversed()) out.add(b)
    }
    return derTlv(0x06, out.toByteArray())
}

internal fun derNull(): ByteArray = byteArrayOf(0x05, 0x00)

internal fun derBitString(bytes: ByteArray): ByteArray = derTlv(0x03, byteArrayOf(0) + bytes)

internal fun derOctetString(bytes: ByteArray): ByteArray = derTlv(0x04, bytes)

internal fun derUtf8String(s: String): ByteArray = derTlv(0x0c, s.encodeToByteArray())

internal fun derUtcTime(millis: Long): ByteArray = derTlv(0x17, utcTimeString(millis).encodeToByteArray())

/** A context-specific, explicitly tagged value: `[n] EXPLICIT`. */
internal fun derExplicit(tagNumber: Int, content: ByteArray): ByteArray =
    derTlv(0xA0 or (tagNumber and 0x1f), content)

// ----- Reading -----

internal class DerTlv(val start: Int, val tag: Int, val content: Int, val length: Int, val next: Int) {
    val contentEnd: Int get() = content + length
}

internal fun readDerTlv(bytes: ByteArray, offset: Int): DerTlv {
    var pos = offset
    val tag = bytes[pos].toInt() and 0xff
    pos++
    var len = bytes[pos].toInt() and 0xff
    pos++
    if (len and 0x80 != 0) {
        val n = len and 0x7f
        len = 0
        repeat(n) {
            len = (len shl 8) or (bytes[pos].toInt() and 0xff)
            pos++
        }
    }
    return DerTlv(offset, tag, pos, len, pos + len)
}

/** The child TLVs of a constructed (SEQUENCE/SET/context) value. */
internal fun derChildren(bytes: ByteArray, tlv: DerTlv): List<DerTlv> {
    val list = ArrayList<DerTlv>()
    var pos = tlv.content
    while (pos < tlv.contentEnd) {
        val child = readDerTlv(bytes, pos)
        list.add(child)
        pos = child.next
    }
    return list
}

internal fun derContent(bytes: ByteArray, tlv: DerTlv): ByteArray =
    bytes.copyOfRange(tlv.content, tlv.contentEnd)

internal fun derRaw(bytes: ByteArray, tlv: DerTlv): ByteArray =
    bytes.copyOfRange(tlv.start, tlv.next)
