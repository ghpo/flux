package org.omarchy.flux.protocol

/**
 * A small facade for the iOS app to call from Swift. Top-level functions are
 * exposed to Swift as `AppKt.<name>(...)`.
 */

fun fluxAppName(): String = "Flux"

/** Generates (or loads) an identity and returns its device ID. */
fun deviceIdentity(deviceId: String): String = LocalCertificate.generate(deviceId).deviceId
