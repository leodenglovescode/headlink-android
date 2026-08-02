// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.privatediscovery

/**
 * The pure decision logic behind Private Headscale IPv6 Discovery.
 *
 * Everything here is a function of its arguments — no Android, no clock, no I/O — so the caching,
 * expiry, failure-override and back-off rules are all directly unit-testable.
 *
 * The overriding design goal is that this feature is event-driven: nothing in this file schedules
 * work. A lookup happens only when a coordination connection actually needs one.
 */
object PrivateDiscoveryPolicy {

  /** A previously discovered address and when it was fetched. */
  data class CacheEntry(val address: String, val fetchedAtEpochMillis: Long)

  /** Which phase of the dial is asking. */
  enum class Stage {
    /** Phase 2: answer from cache only, never touch the network. */
    CACHE_ONLY,
    /** Phase 3: a fresh lookup is permitted. */
    ALLOW_LOOKUP,
  }

  enum class Decision {
    /** Feature off, misconfigured, or nothing usable to offer. */
    NOT_APPLICABLE,
    /** Use the cached address as-is. */
    USE_CACHE,
    /** Perform one authenticated lookup. */
    LOOKUP,
    /**
     * A lookup was wanted but is currently rate-limited or has just failed. Fall back to whatever
     * is cached, even if it is past its max age — a stale address is strictly better than none.
     */
    USE_STALE_CACHE,
  }

  /** How the cache displays in the UI. */
  enum class CacheStatus {
    EMPTY,
    VALID,
    EXPIRED,
  }

  /** Minimum spacing between lookups, so a reconnect storm cannot become a request storm. */
  const val MIN_LOOKUP_INTERVAL_MILLIS: Long = 30_000

  /** Ceiling for the failure back-off. */
  const val MAX_LOOKUP_BACKOFF_MILLIS: Long = 30 * 60_000

  fun cacheStatus(
      config: PrivateDiscoveryConfig,
      cache: CacheEntry?,
      nowMillis: Long
  ): CacheStatus =
      when {
        cache == null -> CacheStatus.EMPTY
        isFresh(config, cache, nowMillis) -> CacheStatus.VALID
        else -> CacheStatus.EXPIRED
      }

  /**
   * Whether [cache] is still within the configured max age.
   *
   * In [CacheAgeUnit.ONLY_ON_FAILURE] mode there is no age limit at all: the address is considered
   * good until a connection using it actually fails.
   */
  fun isFresh(config: PrivateDiscoveryConfig, cache: CacheEntry, nowMillis: Long): Boolean {
    val maxAge = config.maxAgeSeconds() ?: return true
    val age = nowMillis - cache.fetchedAtEpochMillis
    if (age < 0) {
      // Clock moved backwards (timezone change, NTP step, manual set). Treat the entry as expired
      // rather than trusting a nonsensical age.
      return false
    }
    return age <= maxAge * 1000
  }

  /**
   * The core decision.
   *
   * Note what is *not* here: no notion of "time to refresh". Nothing polls. [Stage.ALLOW_LOOKUP] is
   * only ever reached because a real connection attempt just failed, which is exactly what makes a
   * connection failure override the configured cache age.
   */
  fun decide(
      stage: Stage,
      config: PrivateDiscoveryConfig,
      cache: CacheEntry?,
      nowMillis: Long,
      lastLookupAttemptMillis: Long,
      consecutiveFailures: Int
  ): Decision {
    if (!config.isUsable()) return Decision.NOT_APPLICABLE

    if (stage == Stage.CACHE_ONLY) {
      if (cache == null) return Decision.NOT_APPLICABLE
      return if (isFresh(config, cache, nowMillis)) Decision.USE_CACHE else Decision.NOT_APPLICABLE
    }

    if (!lookupAllowed(nowMillis, lastLookupAttemptMillis, consecutiveFailures)) {
      // Rate-limited. Rather than give up entirely, offer an expired cached address as a
      // last resort; it may well still be correct.
      return if (cache != null) Decision.USE_STALE_CACHE else Decision.NOT_APPLICABLE
    }
    return Decision.LOOKUP
  }

  /**
   * Whether a fresh lookup may be issued now.
   *
   * The interval grows exponentially with consecutive failures so a persistently broken endpoint
   * (or a device with no connectivity at all) settles into one attempt every 30 minutes instead of
   * one per reconnect.
   */
  fun lookupAllowed(
      nowMillis: Long,
      lastLookupAttemptMillis: Long,
      consecutiveFailures: Int
  ): Boolean {
    if (lastLookupAttemptMillis <= 0L) return true
    val elapsed = nowMillis - lastLookupAttemptMillis
    if (elapsed < 0) return true // clock moved backwards; don't lock ourselves out
    return elapsed >= backoffMillis(consecutiveFailures)
  }

  fun backoffMillis(consecutiveFailures: Int): Long {
    if (consecutiveFailures <= 0) return MIN_LOOKUP_INTERVAL_MILLIS
    val shift = consecutiveFailures.coerceAtMost(16)
    val scaled = MIN_LOOKUP_INTERVAL_MILLIS shl shift
    return if (scaled <= 0L || scaled > MAX_LOOKUP_BACKOFF_MILLIS) MAX_LOOKUP_BACKOFF_MILLIS
    else scaled
  }

  /**
   * Formats an address and a port as a dial target.
   *
   * The IPv6 literal is bracketed, as required by [java.net.URI] and by Go's net.SplitHostPort on
   * the other side of the bridge.
   */
  fun dialTarget(address: String, port: Int): String = "[$address]:$port"
}
