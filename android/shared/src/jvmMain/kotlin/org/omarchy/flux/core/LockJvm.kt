package org.omarchy.flux.core

private class JvmLock : Lock {
    private val monitor = Any()
    override fun <T> withLock(block: () -> T): T = synchronized(monitor) { block() }
}

actual fun createLock(): Lock = JvmLock()
