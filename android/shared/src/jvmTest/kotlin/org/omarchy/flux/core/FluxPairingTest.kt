package org.omarchy.flux.core

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class FluxPairingTest {
    @Test
    fun pairsTwoDevices() {
        val dir1 = Files.createTempDirectory("flux1").toString()
        val dir2 = Files.createTempDirectory("flux2").toString()
        val phone = Flux(dir1, "iPhone")
        val pc = Flux(dir2, "PC")
        phone.start(17301, 20000..20100)
        pc.start(17302, 20200..20300)
        try {
            // Broadcast discovery does not loop back, so connect directly.
            phone.connectTo("127.0.0.1", pc.tcpPort())

            // Wait until both sides see an online device.
            val deadline = System.currentTimeMillis() + 20_000
            while (System.currentTimeMillis() < deadline) {
                if (phone.snapshot().any { it.online } && pc.snapshot().any { it.online }) break
                Thread.sleep(20)
            }
            val phoneDevice = checkNotNull(phone.snapshot().firstOrNull { it.online }) { "phone saw no device" }
            val pcDevice = checkNotNull(pc.snapshot().firstOrNull { it.online }) { "pc saw no device" }

            // The phone asks to pair.
            val ts = System.currentTimeMillis() / 1000
            phone.pair(phoneDevice.id, ts)

            val inDeadline = System.currentTimeMillis() + 10_000
            while (System.currentTimeMillis() < inDeadline) {
                if (pc.snapshot().any { it.pairState == PairState.Incoming }) break
                Thread.sleep(20)
            }
            assertEquals(PairState.Incoming, pc.snapshot().first { it.id == pcDevice.id }.pairState)

            pc.acceptPair(pcDevice.id)

            val pairedDeadline = System.currentTimeMillis() + 10_000
            while (System.currentTimeMillis() < pairedDeadline) {
                if (phone.snapshot().any { it.paired } && pc.snapshot().any { it.paired }) break
                Thread.sleep(20)
            }
            assertTrue(phone.snapshot().first { it.id == phoneDevice.id }.paired)
            assertTrue(pc.snapshot().first { it.id == pcDevice.id }.paired)

            assertNotNull(phone.trust.get(phoneDevice.id))
            assertNotNull(pc.trust.get(pcDevice.id))
        } finally {
            phone.stop()
            pc.stop()
        }
    }

    @Test
    fun trustStorePersists() {
        val dir = Files.createTempDirectory("flux-trust").toString()
        val store = TrustStore(dir)
        store.put(TrustedDevice("abc", "PC", "desktop", TrustStore.encodeCert(byteArrayOf(1, 2, 3, 4))))
        val reloaded = TrustStore(dir)
        assertEquals("PC", reloaded.get("abc")?.name)
        assertTrue(TrustStore.decodeCert(reloaded.get("abc")!!.certificate).contentEquals(byteArrayOf(1, 2, 3, 4)))
    }
}
