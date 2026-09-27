package org.omarchy.flux.net

import org.junit.Assert.assertTrue
import org.junit.Test
import org.omarchy.flux.protocol.Identity
import org.omarchy.flux.protocol.currentTimeMillis

private class FakeLink : ConnectedLink {
    override fun read(buffer: ByteArray, offset: Int, length: Int): Int = -1
    override fun write(bytes: ByteArray) = Unit
    override fun peerCertificate(): ByteArray = ByteArray(0)
    override fun close() = Unit
}

private fun link(peerId: String, outgoing: Boolean, startedAt: Long): Link =
    Link(FakeLink(), Identity(peerId, "peer", "phone", 8, emptyList(), emptyList()), ByteArray(0), outgoing, startedAt)

class PreferredTest {
    @Test
    fun largerSelfKeepsItsOwnLink() {
        // self "b" is larger than peer "a". The larger device ("b") opened
        // "old", so both sides must keep "old".
        val peerId = "a"
        val now = currentTimeMillis()
        val old = link(peerId, outgoing = true, startedAt = now)
        val next = link(peerId, outgoing = false, startedAt = now)
        assertTrue(preferred(old, next, "b") === old)
    }

    @Test
    fun smallerSelfKeepsThePeersLink() {
        // self "a" is smaller than peer "b". The larger device ("b") opened
        // "next", so both sides must keep "next".
        val peerId = "b"
        val now = currentTimeMillis()
        val old = link(peerId, outgoing = true, startedAt = now)
        val next = link(peerId, outgoing = false, startedAt = now)
        assertTrue(preferred(old, next, "a") === next)
    }

    @Test
    fun newLinkWinsAfterTheRaceWindow() {
        val peerId = "a"
        val now = currentTimeMillis()
        val old = link(peerId, outgoing = true, startedAt = now - RACE_WINDOW_MS - 1)
        val next = link(peerId, outgoing = false, startedAt = now)
        assertTrue(preferred(old, next, "b") === next)
    }
}
