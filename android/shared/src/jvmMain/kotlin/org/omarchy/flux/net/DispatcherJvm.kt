package org.omarchy.flux.net

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

actual val blockingDispatcher: CoroutineDispatcher = Dispatchers.IO
