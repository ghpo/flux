package org.omarchy.flux.protocol

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.ptr
import kotlinx.cinterop.IntVar
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFNumberCreate
import platform.CoreFoundation.kCFNumberSInt32Type
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryRef
import platform.Foundation.NSData
import platform.Foundation.NSFileManager
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
import platform.posix.memcpy

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
    val key = SecKeyCreateWithData(
        unwrapPkcs8(privateKeyPkcs8).toCFData(),
        privateKeyAttributes(),
        null,
    ) ?: error("cannot import the private key")
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
    val manager = NSFileManager.defaultManager
    if (manager.fileExistsAtPath(keyPath) && manager.fileExistsAtPath(certPath)) {
        val key = readFile(keyPath)
        val cert = readFile(certPath)
        if (key != null && cert != null && runCatching { parseCertificate(cert) }.isSuccess) {
            return LocalCertificate(key, cert)
        }
    }
    val created = generateCertificate(NSUUID().UUIDString.replace("-", ""))
    manager.createDirectoryAtPath(dir, withIntermediateDirectories = true, attributes = null, error = null)
    writeFile(keyPath, created.privateKey)
    writeFile(certPath, created.certificate)
    return created
}

@OptIn(ExperimentalForeignApi::class)
private fun rsaKeyAttributes(bits: Int): CFDictionaryRef? = memScoped {
    val dict = CFDictionaryCreateMutable(null, 2, null, null)
    CFDictionaryAddValue(dict, kSecAttrKeyType, kSecAttrKeyTypeRSA)
    val sizePtr = alloc<IntVar>()
    sizePtr.value = bits
    val sizeNumber = CFNumberCreate(null, kCFNumberSInt32Type, sizePtr.ptr.reinterpret())
    CFDictionaryAddValue(dict, kSecAttrKeySizeInBits, sizeNumber)
    dict
}

@OptIn(ExperimentalForeignApi::class)
private fun privateKeyAttributes(): CFDictionaryRef? = memScoped {
    val dict = CFDictionaryCreateMutable(null, 2, null, null)
    CFDictionaryAddValue(dict, kSecAttrKeyType, kSecAttrKeyTypeRSA)
    CFDictionaryAddValue(dict, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
    dict
}

@OptIn(ExperimentalForeignApi::class)
private fun CFDataRef?.toByteArray(): ByteArray {
    if (this == null) return ByteArray(0)
    val length = CFDataGetLength(this).toInt()
    val ptr = CFDataGetBytePtr(this) ?: return ByteArray(0)
    return ptr.readBytes(length)
}

@OptIn(ExperimentalForeignApi::class)
private fun ByteArray.toCFData(): CFDataRef? = usePinned { pinned ->
    CFDataCreate(null, pinned.addressOf(0).reinterpret(), size.toLong())
}

@OptIn(ExperimentalForeignApi::class)
private fun ByteArray.toNSData(): NSData = usePinned { pinned ->
    NSData.create(bytes = pinned.addressOf(0), length = size.toULong())
}

@OptIn(ExperimentalForeignApi::class)
private fun NSData.toByteArray(): ByteArray {
    val size = length.toInt()
    if (size == 0) return ByteArray(0)
    val result = ByteArray(size)
    result.usePinned { pinned ->
        memcpy(pinned.addressOf(0), bytes, length)
    }
    return result
}

private fun readFile(path: String): ByteArray? = NSData.dataWithContentsOfFile(path)?.toByteArray()

@OptIn(ExperimentalForeignApi::class)
private fun writeFile(path: String, data: ByteArray) {
    data.toNSData().writeToFile(path, atomically = true)
}
