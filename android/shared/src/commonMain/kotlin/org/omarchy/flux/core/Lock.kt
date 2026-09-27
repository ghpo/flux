package org.omarchy.flux.core

/** A minimal cross-platform mutex. */
interface Lock {
    fun <T> withLock(block: () -> T): T
}

expect fun createLock(): Lock
