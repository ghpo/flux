package org.omarchy.flux.core

import kotlin.io.encoding.Base64
import kotlinx.serialization.Serializable
import org.omarchy.flux.protocol.json

enum class PairState { None, Requested, Incoming, Paired }

/** A paired device. Flux pins its certificate. */
@Serializable
data class TrustedDevice(
    val id: String,
    val name: String,
    val type: String,
    val certificate: String,
    val lastIp: String = "",
    val isFlux: Boolean = false,
)

/** The state of one device, as the UI renders it. */
data class DeviceUi(
    val id: String,
    val name: String,
    val type: String,
    val ip: String,
    val isFlux: Boolean,
    val paired: Boolean,
    val online: Boolean,
    val pairState: PairState,
    val pairKey: String,
    val pairOutgoing: Boolean,
)

expect fun readTextFile(path: String): String?

expect fun writeTextFile(path: String, text: String)

/** The list of paired devices, stored as JSON next to the identity. */
class TrustStore(private val dir: String) {
    private val devices = LinkedHashMap<String, TrustedDevice>()
    private val file = "$dir/trusted.json"

    init {
        val text = readTextFile(file)
        if (text != null) {
            runCatching { json.decodeFromString<List<TrustedDevice>>(text) }
                .getOrNull()?.forEach { devices[it.id] = it }
        }
    }

    fun get(id: String): TrustedDevice? = devices[id]

    fun all(): List<TrustedDevice> = devices.values.toList()

    fun put(d: TrustedDevice) {
        devices[d.id] = d
        save()
    }

    fun update(id: String, fn: (TrustedDevice) -> TrustedDevice) {
        val d = devices[id] ?: return
        put(fn(d))
    }

    fun remove(id: String) {
        devices.remove(id)
        save()
    }

    private fun save() {
        writeTextFile(file, json.encodeToString(devices.values.toList()))
    }

    companion object {
        fun encodeCert(der: ByteArray): String = Base64.encode(der)
        fun decodeCert(value: String): ByteArray = Base64.decode(value)
    }
}
