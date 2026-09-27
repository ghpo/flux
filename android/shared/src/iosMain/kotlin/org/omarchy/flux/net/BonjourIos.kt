@file:OptIn(
    kotlinx.cinterop.ExperimentalForeignApi::class,
    kotlinx.cinterop.BetaInteropApi::class,
)

package org.omarchy.flux.net

import kotlinx.cinterop.ObjCSignatureOverride
import kotlinx.cinterop.allocArrayOf
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.readBytes
import platform.Foundation.NSData
import platform.Foundation.NSDefaultRunLoopMode
import platform.Foundation.NSMutableData
import platform.Foundation.NSNetService
import platform.Foundation.NSNetServiceBrowser
import platform.Foundation.NSNetServiceBrowserDelegateProtocol
import platform.Foundation.NSNetServiceDelegateProtocol
import platform.Foundation.NSRunLoop
import platform.Foundation.appendData
import platform.darwin.NSObject

private const val SERVICE_TYPE = "_kdeconnect._udp"

private class BonjourMdns : MdnsService {
    private var service: NSNetService? = null
    private var browser: NSNetServiceBrowser? = null
    private var browserDelegate: BonjourBrowserDelegate? = null

    override fun publish(deviceId: String, port: Int, txt: Map<String, String>) {
        service?.stop()
        val s = NSNetService(domain = "local.", type = SERVICE_TYPE, name = deviceId, port = port)
        s.setTXTRecordData(createTxtData(txt))
        s.includesPeerToPeer = true
        s.publish()
        service = s
    }

    override fun browse(callback: (MdnsPeer) -> Unit) {
        stopBrowse()
        val b = NSNetServiceBrowser()
        val d = BonjourBrowserDelegate(callback)
        b.delegate = d
        b.includesPeerToPeer = true
        b.scheduleInRunLoop(NSRunLoop.mainRunLoop, NSDefaultRunLoopMode)
        b.searchForServicesOfType(SERVICE_TYPE, inDomain = "local.")
        browser = b
        browserDelegate = d
    }

    override fun stop() {
        stopBrowse()
        service?.stop()
        service = null
    }

    private fun stopBrowse() {
        browser?.stop()
        browser?.removeFromRunLoop(NSRunLoop.mainRunLoop, NSDefaultRunLoopMode)
        browser?.delegate = null
        browser = null
        browserDelegate = null
    }
}

actual fun mdnsService(): MdnsService = BonjourMdns()

private class BonjourBrowserDelegate(
    private val callback: (MdnsPeer) -> Unit,
) : NSObject(), NSNetServiceBrowserDelegateProtocol {
    private val resolver = ResolveDelegate(callback)

    @ObjCSignatureOverride
    override fun netServiceBrowser(browser: NSNetServiceBrowser, didFindService: NSNetService, moreComing: Boolean) {
        didFindService.delegate = resolver
        didFindService.resolveWithTimeout(10.0)
    }

    @ObjCSignatureOverride
    override fun netServiceBrowser(browser: NSNetServiceBrowser, didRemoveService: NSNetService, moreComing: Boolean) = Unit

    @ObjCSignatureOverride
    override fun netServiceBrowser(browser: NSNetServiceBrowser, didFindDomain: String, moreComing: Boolean) = Unit

    @ObjCSignatureOverride
    override fun netServiceBrowser(browser: NSNetServiceBrowser, didRemoveDomain: String, moreComing: Boolean) = Unit

    @ObjCSignatureOverride
    override fun netServiceBrowser(browser: NSNetServiceBrowser, didNotSearch: Map<Any?, *>) = Unit

    override fun netServiceBrowserWillSearch(browser: NSNetServiceBrowser) = Unit

    override fun netServiceBrowserDidStopSearch(browser: NSNetServiceBrowser) = Unit
}

private class ResolveDelegate(
    private val callback: (MdnsPeer) -> Unit,
) : NSObject(), NSNetServiceDelegateProtocol {
    override fun netServiceDidResolveAddress(sender: NSNetService) {
        val ip = firstIpv4(sender) ?: return
        val attrs = txtByteToMap(sender.TXTRecordData()?.toByteArray() ?: ByteArray(0))
        callback(
            MdnsPeer(
                deviceId = attrs["id"] ?: sender.name,
                name = attrs["name"] ?: sender.name,
                type = attrs["type"] ?: "",
                ip = ip,
                port = sender.port.toInt(),
                protocol = attrs["protocol"]?.toIntOrNull() ?: 0,
            ),
        )
    }

    @ObjCSignatureOverride
    override fun netService(sender: NSNetService, didNotResolve: Map<Any?, *>) = Unit

    @ObjCSignatureOverride
    override fun netService(sender: NSNetService, didNotPublish: Map<Any?, *>) = Unit

    override fun netServiceWillPublish(sender: NSNetService) = Unit
    override fun netServiceDidPublish(sender: NSNetService) = Unit
    override fun netServiceDidStop(sender: NSNetService) = Unit
    override fun netServiceWillResolve(sender: NSNetService) = Unit
}

private fun createTxtData(attributes: Map<String, String>): NSData {
    val data = NSMutableData()
    for ((key, value) in attributes) {
        val record = "$key=$value".encodeToByteArray()
        if (record.size > 255) continue
        data.appendData(byteArrayOf(record.size.toByte()).toNSData())
        data.appendData(record.toNSData())
    }
    return data
}

private fun ByteArray.toNSData(): NSData = memScoped {
    NSData.create(bytes = allocArrayOf(this@toNSData), length = this@toNSData.size.toULong())
}

private fun NSData.toByteArray(): ByteArray = bytes?.readBytes(length.toInt()) ?: ByteArray(0)

private fun txtByteToMap(data: ByteArray): Map<String, String> {
    val map = mutableMapOf<String, String>()
    var i = 0
    while (i < data.size) {
        val len = data[i].toInt() and 0xFF
        i++
        if (i + len > data.size) break
        val entry = data.copyOfRange(i, i + len).decodeToString()
        val eq = entry.indexOf('=')
        if (eq >= 0) map[entry.substring(0, eq)] = entry.substring(eq + 1)
        i += len
    }
    return map
}

private fun firstIpv4(service: NSNetService): String? {
    val addresses = service.addresses ?: return null
    for (address in addresses) {
        val bytes = (address as? NSData)?.toByteArray() ?: continue
        if (bytes.size < 8) continue
        if (bytes[1].toInt() and 0xFF != 2) continue // AF_INET
        return (4 until 8).joinToString(".") { (bytes[it].toInt() and 0xFF).toString() }
    }
    return null
}
