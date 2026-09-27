package org.omarchy.flux.core

import platform.Foundation.NSLock

private class IosLock : Lock {
    private val lock = NSLock()
    override fun <T> withLock(block: () -> T): T {
        lock.lock()
        try {
            return block()
        } finally {
            lock.unlock()
        }
    }
}

actual fun createLock(): Lock = IosLock()
