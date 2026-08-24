package io.github.biulight.phone_identity

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProbeKeyStoreTest {
    @Test
    fun acceptsOnlyCanonicalProbeAliases() {
        assertTrue(
            ProbeKeyStore.isValidProbeAlias(
                "age-plugin-phone-poc-123e4567-e89b-42d3-a456-426614174000",
            ),
        )
        assertFalse(ProbeKeyStore.isValidProbeAlias("age-plugin-phone-production-key"))
        assertFalse(
            ProbeKeyStore.isValidProbeAlias(
                "age-plugin-phone-poc-123e4567-e89b-12d3-a456-426614174000",
            ),
        )
        assertFalse(
            ProbeKeyStore.isValidProbeAlias(
                "age-plugin-phone-poc-123E4567-E89B-42D3-A456-426614174000",
            ),
        )
    }
}
