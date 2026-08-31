package io.github.biulight.phone_identity

import java.nio.file.Files
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WifiAutoListenTest {
    @After
    fun resetCoordinator() {
        WifiAutoListenForegroundCoordinator.resetForTest()
    }

    @Test
    fun settingDefaultsOffPersistsAndFailsClosedOnCorruption() {
        val directory = Files.createTempDirectory("wifi-auto-listen-test").toFile()
        try {
            val setting = WifiAutoListenSetting(directory)
            assertFalse(setting.enabled())
            setting.setEnabled(true)
            assertTrue(WifiAutoListenSetting(directory).enabled())
            directory.resolve("wifi-auto-listen-v1").writeBytes(byteArrayOf(1, 2, 3))
            assertFalse(WifiAutoListenSetting(directory).enabled())
            setting.setEnabled(false)
            assertFalse(setting.enabled())
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun foregroundStateIsDeliveredAcrossRegistration() {
        val states = mutableListOf<Boolean>()
        val owner = Any()
        WifiAutoListenForegroundCoordinator.onStart()
        WifiAutoListenForegroundCoordinator.register(owner, states::add)
        WifiAutoListenForegroundCoordinator.onStop()
        WifiAutoListenForegroundCoordinator.unregister(owner)
        WifiAutoListenForegroundCoordinator.onStart()
        assertEquals(listOf(true, false), states)
    }

    @Test
    fun bindRetryBackoffIsBounded() {
        assertEquals(
            listOf(1_000L, 2_000L, 4_000L, 8_000L, 16_000L, 30_000L, 30_000L),
            (0..6).map(WifiAutoListenRetryPolicy::bindDelay),
        )
    }
}
