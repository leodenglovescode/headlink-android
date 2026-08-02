// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.privatediscovery

import com.tailscale.ipn.privatediscovery.PrivateDiscoveryPolicy.CacheEntry
import com.tailscale.ipn.privatediscovery.PrivateDiscoveryPolicy.CacheStatus
import com.tailscale.ipn.privatediscovery.PrivateDiscoveryPolicy.Decision
import com.tailscale.ipn.privatediscovery.PrivateDiscoveryPolicy.Stage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Cache, expiry, failure-override and back-off rules. */
class PrivateDiscoveryPolicyTest {

  private val now = 1_800_000_000_000L // a fixed "now", in epoch millis
  private val hour = 3_600_000L

  private val enabled =
      PrivateDiscoveryConfig(
          enabled = true,
          lookupUrl = "https://lookup.example.com/current-ip",
          secret = "secret",
          cacheAgeValue = 24,
          cacheAgeUnit = CacheAgeUnit.HOURS)

  private val disabled = enabled.copy(enabled = false)

  private fun cacheAgedHours(h: Long) = CacheEntry("2409:8a00:1234:5678::abcd", now - h * hour)

  private fun decide(
      stage: Stage,
      config: PrivateDiscoveryConfig = enabled,
      cache: CacheEntry? = null,
      lastAttempt: Long = 0,
      failures: Int = 0
  ) = PrivateDiscoveryPolicy.decide(stage, config, cache, now, lastAttempt, failures)

  // Requirement 1: with the feature disabled nothing at all happens.
  @Test
  fun disabledIsAlwaysNotApplicable() {
    assertEquals(Decision.NOT_APPLICABLE, decide(Stage.CACHE_ONLY, disabled, cacheAgedHours(1)))
    assertEquals(Decision.NOT_APPLICABLE, decide(Stage.ALLOW_LOOKUP, disabled, cacheAgedHours(1)))
    assertEquals(Decision.NOT_APPLICABLE, decide(Stage.ALLOW_LOOKUP, disabled, null))
  }

  @Test
  fun incompleteConfigurationIsNotApplicable() {
    assertEquals(
        Decision.NOT_APPLICABLE,
        decide(Stage.ALLOW_LOOKUP, enabled.copy(secret = ""), cacheAgedHours(1)))
    assertEquals(
        Decision.NOT_APPLICABLE,
        decide(Stage.ALLOW_LOOKUP, enabled.copy(lookupUrl = "http://insecure.example/ip")))
    assertEquals(
        Decision.NOT_APPLICABLE, decide(Stage.ALLOW_LOOKUP, enabled.copy(lookupUrl = "nonsense")))
    assertEquals(
        Decision.NOT_APPLICABLE,
        decide(Stage.ALLOW_LOOKUP, enabled.copy(authHeader = "bad header"), cacheAgedHours(1)))
  }

  // Requirement 3: a valid cached address is used, and phase 2 never triggers a lookup.
  @Test
  fun freshCacheIsUsedWithoutLookup() {
    assertEquals(Decision.USE_CACHE, decide(Stage.CACHE_ONLY, cache = cacheAgedHours(2)))
  }

  // Requirement 4: an expired cache means phase 2 declines, so phase 3 performs a lookup.
  @Test
  fun expiredCacheFallsThroughToLookup() {
    assertEquals(Decision.NOT_APPLICABLE, decide(Stage.CACHE_ONLY, cache = cacheAgedHours(25)))
    assertEquals(Decision.LOOKUP, decide(Stage.ALLOW_LOOKUP, cache = cacheAgedHours(25)))
  }

  @Test
  fun emptyCacheGoesStraightToLookup() {
    assertEquals(Decision.NOT_APPLICABLE, decide(Stage.CACHE_ONLY, cache = null))
    assertEquals(Decision.LOOKUP, decide(Stage.ALLOW_LOOKUP, cache = null))
  }

  // Requirement 5: a connection failure overrides the cache age. Phase 3 is reached even when the
  // cached address is younger than the limit, and it asks for a fresh lookup.
  @Test
  fun connectionFailureOverridesCacheAge() {
    val young = cacheAgedHours(2) // well inside the 24h limit
    assertEquals(Decision.USE_CACHE, decide(Stage.CACHE_ONLY, cache = young))
    assertEquals(
        "a failed dial of the cached address must force a refresh, not reuse it",
        Decision.LOOKUP,
        decide(Stage.ALLOW_LOOKUP, cache = young))
  }

  // Requirement 21: staleness alone never causes work; only a real dial does. There is no
  // "time to refresh" concept anywhere in the policy.
  @Test
  fun staleCacheDoesNotTriggerAnythingByItself() {
    // A very old cache still produces NOT_APPLICABLE at phase 2: nothing is scheduled, and the
    // only way to reach LOOKUP is for a caller to have already failed a dial and asked for
    // ALLOW_LOOKUP.
    assertEquals(Decision.NOT_APPLICABLE, decide(Stage.CACHE_ONLY, cache = cacheAgedHours(100)))
  }

  // Requirement 22: repeated failures back off instead of looping.
  @Test
  fun repeatedFailuresBackOff() {
    // Immediately after an attempt, another lookup is refused.
    assertEquals(
        Decision.USE_STALE_CACHE,
        decide(
            Stage.ALLOW_LOOKUP,
            cache = cacheAgedHours(30),
            lastAttempt = now - 1_000,
            failures = 1))
    // With no cache at all there is simply nothing to offer.
    assertEquals(
        Decision.NOT_APPLICABLE,
        decide(Stage.ALLOW_LOOKUP, cache = null, lastAttempt = now - 1_000, failures = 1))
    // Once the back-off has elapsed, a lookup is allowed again.
    assertEquals(
        Decision.LOOKUP,
        decide(
            Stage.ALLOW_LOOKUP,
            cache = null,
            lastAttempt = now - PrivateDiscoveryPolicy.MAX_LOOKUP_BACKOFF_MILLIS - 1,
            failures = 10))
  }

  @Test
  fun backoffGrowsAndIsCapped() {
    assertEquals(
        PrivateDiscoveryPolicy.MIN_LOOKUP_INTERVAL_MILLIS, PrivateDiscoveryPolicy.backoffMillis(0))
    assertTrue(PrivateDiscoveryPolicy.backoffMillis(3) > PrivateDiscoveryPolicy.backoffMillis(1))
    assertEquals(
        PrivateDiscoveryPolicy.MAX_LOOKUP_BACKOFF_MILLIS,
        PrivateDiscoveryPolicy.backoffMillis(1000))
    assertTrue(PrivateDiscoveryPolicy.backoffMillis(1000) > 0)
  }

  @Test
  fun firstLookupIsAlwaysAllowed() {
    assertTrue(PrivateDiscoveryPolicy.lookupAllowed(now, 0, 0))
  }

  @Test
  fun clockGoingBackwardsDoesNotLockOutLookups() {
    assertTrue(PrivateDiscoveryPolicy.lookupAllowed(now, now + hour, 3))
  }

  @Test
  fun clockGoingBackwardsExpiresTheCache() {
    val fromTheFuture = CacheEntry("2409:8a00::1", now + hour)
    assertFalse(PrivateDiscoveryPolicy.isFresh(enabled, fromTheFuture, now))
  }

  @Test
  fun onlyOnFailureModeNeverExpiresByAge() {
    val config = enabled.copy(cacheAgeUnit = CacheAgeUnit.ONLY_ON_FAILURE)
    assertNull(config.maxAgeSeconds())
    assertTrue(PrivateDiscoveryPolicy.isFresh(config, cacheAgedHours(10_000), now))
    assertEquals(Decision.USE_CACHE, decide(Stage.CACHE_ONLY, config, cacheAgedHours(10_000)))
    // But a failed dial still forces a refresh.
    assertEquals(Decision.LOOKUP, decide(Stage.ALLOW_LOOKUP, config, cacheAgedHours(10_000)))
  }

  @Test
  fun maxAgeIsClampedToTheMinimum() {
    val oneMinute = enabled.copy(cacheAgeValue = 1, cacheAgeUnit = CacheAgeUnit.MINUTES)
    assertEquals(MIN_CACHE_AGE_SECONDS, oneMinute.maxAgeSeconds())
  }

  @Test
  fun cacheStatusRendersTheThreeStates() {
    assertEquals(CacheStatus.EMPTY, PrivateDiscoveryPolicy.cacheStatus(enabled, null, now))
    assertEquals(
        CacheStatus.VALID, PrivateDiscoveryPolicy.cacheStatus(enabled, cacheAgedHours(1), now))
    assertEquals(
        CacheStatus.EXPIRED, PrivateDiscoveryPolicy.cacheStatus(enabled, cacheAgedHours(48), now))
  }

  @Test
  fun dialTargetBracketsTheLiteral() {
    assertEquals(
        "[2409:8a00:1234:5678::abcd]:443",
        PrivateDiscoveryPolicy.dialTarget("2409:8a00:1234:5678::abcd", 443))
    // The port from the failed dial is preserved, including controlhttp's port 80 attempt.
    assertEquals("[2409:8a00::1]:80", PrivateDiscoveryPolicy.dialTarget("2409:8a00::1", 80))
  }

  @Test
  fun validationRules() {
    assertNull(validateLookupUrl("https://lookup.example.com/ip"))
    assertNull(validateLookupUrl("  https://lookup.example.com/ip  "))
    assertEquals(ValidationError.EMPTY, validateLookupUrl(""))
    assertEquals(ValidationError.NOT_HTTPS, validateLookupUrl("http://lookup.example.com/ip"))
    assertEquals(ValidationError.NOT_HTTPS, validateLookupUrl("ftp://lookup.example.com/ip"))
    assertEquals(ValidationError.NO_HOST, validateLookupUrl("https:///ip"))

    assertNull(validateAuthHeader("X-Sync-Secret"))
    assertNull(validateAuthHeader("Authorization"))
    assertNull(validateAuthHeader("  X-Sync-Secret  "))
    assertEquals(ValidationError.EMPTY, validateAuthHeader(""))
    assertEquals(ValidationError.INVALID_HEADER_NAME, validateAuthHeader("X Sync"))
    assertEquals(ValidationError.INVALID_HEADER_NAME, validateAuthHeader("X-Sync:Secret"))
    assertEquals(ValidationError.INVALID_HEADER_NAME, validateAuthHeader("X-Sync\r\nOther: 1"))

    assertNull(validateTimeoutSeconds("10"))
    assertNull(validateTimeoutSeconds(" 2 "))
    assertNull(validateTimeoutSeconds("60"))
    assertEquals(ValidationError.OUT_OF_RANGE, validateTimeoutSeconds("1"))
    assertEquals(ValidationError.OUT_OF_RANGE, validateTimeoutSeconds("61"))
    assertEquals(ValidationError.NOT_A_URL, validateTimeoutSeconds("abc"))

    assertNull(validateCacheAgeValue("24", CacheAgeUnit.HOURS))
    assertNull(validateCacheAgeValue("5", CacheAgeUnit.MINUTES))
    assertEquals(ValidationError.OUT_OF_RANGE, validateCacheAgeValue("4", CacheAgeUnit.MINUTES))
    assertEquals(ValidationError.OUT_OF_RANGE, validateCacheAgeValue("0", CacheAgeUnit.HOURS))
    assertEquals(ValidationError.NOT_A_URL, validateCacheAgeValue("x", CacheAgeUnit.HOURS))
    // The value box is irrelevant in "only on failure" mode.
    assertNull(validateCacheAgeValue("", CacheAgeUnit.ONLY_ON_FAILURE))
  }
}
