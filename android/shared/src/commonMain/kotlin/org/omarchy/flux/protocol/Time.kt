package org.omarchy.flux.protocol

import kotlin.time.Clock

/** Returns the current time in milliseconds since the Unix epoch. */
fun currentTimeMillis(): Long = Clock.System.now().toEpochMilliseconds()
