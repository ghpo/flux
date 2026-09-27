@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package org.omarchy.flux.protocol

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.cinterop.UByteVar
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFNumberCreate
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFNumberIntType
import platform.Foundation.NSUUID
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyCreateRandomKey
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyCreateWithData
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPrivate
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeRSA
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import platform.posix.fseek
import platform.posix.ftell
import platform.posix.fwrite
import platform.posix.mkdir
import platform.posix.SEEK_END
import platform.posix.SEEK_SET
import platform.posix.int32_tVar

private const val KEY_FILE = "privateKey.der"
private const val CERT_FILE = "certificate.der"

actual fun generateRsaKeyPair(bits: Int): RsaKeyPair {
    val privateKey = SecKeyCreateRandomKey(rsaKeyAttributes(bits), null)
        ?: error("cannot generate an RSA key")
    val publicKey = SecKeyCopyPublicKey(privateKey) ?: error("cannot read the public key")
    val privatePkcs1 = SecKeyCopyExternalRepresentation(privateKey, null).toByteArray()
    val publicPkcs1 = SecKeyCopyExternalRepresentation(publicKey, null).toByteArray()
    return RsaKeyPair(wrapRsaSpki(publicPkcs1), wrapPkcs8(privatePkcs1))
}

actual fun rsaSignSha256(privateKeyPkcs8: ByteArray, message: ByteArray): ByteArray {
    val key = SecKeyCreateWithData(unwrapPkcs8(privateKeyPkcs8).toCFData(), privateKeyAttributes(), null)
        ?: error("cannot import the private key")
    val signature = SecKeyCreateSignature(
        key,
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
        message.toCFData(),
        null,
    ) ?: error("cannot sign")
    return signature.toByteArray()
}

actual fun loadOrCreateCertificate(dir: String): LocalCertificate {
    val keyPath = "$dir/$KEY_FILE"
    val certPath = "$dir/$CERT_FILE"
    val key = readFile(keyPath)
    val cert = readFile(certPath)
    if (key != null && cert != null && runCatching { parseCertificate(cert) }.isSuccess) {
        return LocalCertificate(key, cert)
    }
    val created = generateCertificate(NSUUID().UUIDString.replace("-", ""))
    mkdir(dir, 493u)
    writeFile(keyPath, created.privateKey)
    writeFile(certPath, created.certificate)
    return created
}

private fun rsaKeyAttributes(bits: Int): CFDictionaryRef? = memScoped {
    val dict = CFDictionaryCreateMutable(null, 2, null, null)
    CFDictionaryAddValue(dict, kSecAttrKeyType, kSecAttrKeyTypeRSA)
    val sizeVar = alloc<int32_tVar>().apply { value = bits }
    val sizeNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, sizeVar.ptr)
    CFDictionaryAddValue(dict, kSecAttrKeySizeInBits, sizeNumber)
    dict
}

private fun privateKeyAttributes(): CFDictionaryRef? = memScoped {
    val dict = CFDictionaryCreateMutable(null, 2, null, null)
    CFDictionaryAddValue(dict, kSecAttrKeyType, kSecAttrKeyTypeRSA)
    CFDictionaryAddValue(dict, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
    dict
}

private fun CFDataRef?.toByteArray(): ByteArray {
    if (this == null) return ByteArray(0)
    val length = CFDataGetLength(this).toInt()
    val ptr = CFDataGetBytePtr(this) ?: return ByteArray(0)
    return ptr.readBytes(length)
}

private fun ByteArray.toCFData(): CFDataRef? = usePinned { pinned ->
    CFDataCreate(null, pinned.addressOf(0).reinterpret<UByteVar>(), size.toLong())
}

private fun writeFile(path: String, data: ByteArray) {
    val file = fopen(path, "wb") ?: error("cannot open $path for writing")
    try {
        data.usePinned { pinned ->
            fwrite(pinned.addressOf(0).reinterpret<UByteVar>(), 1uL, data.size.toULong(), file)
        }
    } finally {
        fclose(file)
    }
}

private fun readFile(path: String): ByteArray? {
    val file = fopen(path, "rb") ?: return null
    try {
        if (fseek(file, 0L, SEEK_END) != 0) return null
        val size = ftell(file)
        if (size < 0L) return null
        if (fseek(file, 0L, SEEK_SET) != 0) return null
        val buffer = ByteArray(size.toInt())
        buffer.usePinned { pinned ->
            fread(pinned.addressOf(0).reinterpret<UByteVar>(), 1uL, size.toULong(), file)
        }
        return buffer
    } finally {
        fclose(file)
    }
}
