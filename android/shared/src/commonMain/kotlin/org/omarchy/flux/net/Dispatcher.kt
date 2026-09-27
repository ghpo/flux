package org.omarchy.flux.net

import kotlinx.coroutines.CoroutineDispatcher

/**
 * The dispatcher for blocking socket and TLS work. The JVM has a dedicated IO
 * pool; Kotlin/Native only exposes the default worker dispatcher.
 */
expect val blockingDispatcher: CoroutineDispatcher
