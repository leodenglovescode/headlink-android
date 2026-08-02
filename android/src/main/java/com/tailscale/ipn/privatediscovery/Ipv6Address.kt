// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.privatediscovery

/**
 * Strict, dependency-free parsing and validation of the IPv6 address returned by the lookup
 * endpoint.
 *
 * Two response shapes are accepted: a bare address on one line (`2001:db8::1\n`) and a small JSON
 * document containing one (`{"ipv6":"2001:db8::1"}`). The JSON form is handled without a JSON
 * library and without caring about the field name — only string *values* are considered, and the
 * first one that survives full validation wins. That keeps this client working if the endpoint's
 * schema is tweaked, while never loosening what counts as an acceptable address.
 *
 * This deliberately does not use [java.net.InetAddress.getByName]: that helper falls back to DNS
 * resolution for anything it cannot parse as a literal, which would turn a malformed response into
 * a surprise network request. Everything here is pure string/bit manipulation, so it is fully
 * covered by JVM unit tests and can never touch the network.
 */
object Ipv6Address {

  /** Why a response body was rejected. Kept coarse so it is always safe to show or log. */
  enum class Rejection {
    EMPTY,
    NOT_IPV6,
    UNSPECIFIED,
    LOOPBACK,
    MULTICAST,
    LINK_LOCAL,
    SITE_LOCAL,
    UNIQUE_LOCAL,
    IPV4_MAPPED,
  }

  sealed class Result {
    data class Valid(val address: String) : Result()

    data class Invalid(val reason: Rejection) : Result()
  }

  /**
   * Parses and validates a lookup response body.
   *
   * Surrounding whitespace, CR and LF are trimmed, so both `"2001:db8::1"` and `" 2001:db8::1\r\n"`
   * are accepted, as is a JSON object or array containing an address as a string value. The
   * returned address is the lower-cased literal, suitable for use inside `[...]:port`.
   */
  fun parseLookupResponse(body: String): Result {
    val text = body.trim()
    if (text.isEmpty()) return Result.Invalid(Rejection.EMPTY)

    if (text.startsWith("{") || text.startsWith("[")) return parseJson(text)
    return parseAddress(text)
  }

  /**
   * Validates a single candidate address, which must be a bare IPv6 literal and nothing else.
   *
   * This is the only path by which an address can be accepted; the JSON reader feeds candidates
   * through here rather than relaxing any rule of its own.
   */
  private fun parseAddress(candidate: String): Result {
    val text = candidate.trim().lowercase()
    if (text.isEmpty()) return Result.Invalid(Rejection.EMPTY)

    // A zone identifier (fe80::1%wlan0) is meaningless on a remote address, and a dot means either
    // plain IPv4 or an IPv4-mapped form; neither is usable as a global destination.
    if (text.contains('%')) return Result.Invalid(Rejection.NOT_IPV6)
    if (text.contains('.')) {
      return Result.Invalid(if (text.contains(':')) Rejection.IPV4_MAPPED else Rejection.NOT_IPV6)
    }

    val bytes = parseLiteral(text) ?: return Result.Invalid(Rejection.NOT_IPV6)

    classify(bytes)?.let {
      return Result.Invalid(it)
    }
    return Result.Valid(text)
  }

  /**
   * Finds the first usable address among the string values of a JSON document.
   *
   * If none is usable, the rejection reported is the one from the first candidate that at least
   * looked address-shaped, so a response carrying an IPv4 address or a link-local address produces
   * the specific complaint rather than a generic one.
   */
  private fun parseJson(text: String): Result {
    val candidates = jsonStringValues(text)
    if (candidates.isEmpty()) return Result.Invalid(Rejection.NOT_IPV6)

    var firstInteresting: Rejection? = null
    for (candidate in candidates) {
      when (val result = parseAddress(candidate)) {
        is Result.Valid -> return result
        is Result.Invalid -> {
          // A JSON document legitimately contains strings that were never meant to be addresses
          // (timestamps, hostnames); only remember reasons that suggest a real attempt at one.
          if (firstInteresting == null && result.reason != Rejection.NOT_IPV6) {
            firstInteresting = result.reason
          }
        }
      }
    }
    return Result.Invalid(firstInteresting ?: Rejection.NOT_IPV6)
  }

  /**
   * Extracts every double-quoted string from a JSON document, handling backslash escapes well
   * enough not to be confused by them.
   *
   * Keys and values are not distinguished: a key is simply a candidate that will fail validation.
   * Escape sequences are not decoded, because no valid IPv6 literal contains one — a candidate with
   * an escape in it is guaranteed to be rejected anyway.
   */
  private fun jsonStringValues(text: String): List<String> {
    val out = mutableListOf<String>()
    val current = StringBuilder()
    var inString = false
    var escaped = false
    for (c in text) {
      when {
        escaped -> {
          current.append(c)
          escaped = false
        }
        c == '\\' && inString -> escaped = true
        c == '"' -> {
          if (inString) {
            out.add(current.toString())
            current.setLength(0)
          }
          inString = !inString
        }
        inString -> current.append(c)
      }
      if (out.size >= MAX_JSON_STRINGS) break
    }
    return out
  }

  /** Bound on how many strings a single response is allowed to make this client examine. */
  private const val MAX_JSON_STRINGS = 64

  /**
   * Returns the reason [bytes] is unusable as a public destination, or null if it is acceptable.
   *
   * Anything that is not a routable unicast address on the public Internet is refused: connecting
   * to it could never reach the home server, and in some cases would reach something else on the
   * local network instead.
   */
  private fun classify(bytes: ByteArray): Rejection? {
    fun b(i: Int): Int = bytes[i].toInt() and 0xff

    if (bytes.all { it.toInt() == 0 }) return Rejection.UNSPECIFIED

    // ::1
    if ((0..14).all { bytes[it].toInt() == 0 } && bytes[15].toInt() == 1) return Rejection.LOOPBACK

    // ff00::/8
    if (b(0) == 0xff) return Rejection.MULTICAST

    // fe80::/10
    if (b(0) == 0xfe && (b(1) and 0xc0) == 0x80) return Rejection.LINK_LOCAL

    // fec0::/10 (deprecated site-local)
    if (b(0) == 0xfe && (b(1) and 0xc0) == 0xc0) return Rejection.SITE_LOCAL

    // fc00::/7 (unique local — not globally routable)
    if ((b(0) and 0xfe) == 0xfc) return Rejection.UNIQUE_LOCAL

    // ::ffff:0:0/96 (IPv4-mapped, in hex form) and ::/96 (IPv4-compatible).
    if ((0..9).all { bytes[it].toInt() == 0 }) {
      if (b(10) == 0xff && b(11) == 0xff) return Rejection.IPV4_MAPPED
      if (b(10) == 0 && b(11) == 0) return Rejection.IPV4_MAPPED
    }

    return null
  }

  /**
   * Parses a bare IPv6 literal (no zone, no embedded IPv4) into 16 bytes, or null if it is not a
   * well-formed literal.
   */
  private fun parseLiteral(text: String): ByteArray? {
    if (text.isEmpty()) return null

    val doubleColon = text.indexOf("::")
    if (doubleColon >= 0 && text.indexOf("::", doubleColon + 1) >= 0) {
      // More than one "::" is ambiguous and therefore invalid.
      return null
    }

    val head: List<String>
    val tail: List<String>
    if (doubleColon >= 0) {
      val before = text.substring(0, doubleColon)
      val after = text.substring(doubleColon + 2)
      head = if (before.isEmpty()) emptyList() else before.split(':')
      tail = if (after.isEmpty()) emptyList() else after.split(':')
    } else {
      head = text.split(':')
      tail = emptyList()
    }

    if (doubleColon < 0 && head.size != 8) return null
    if (head.size + tail.size > 8) return null
    if (doubleColon >= 0 && head.size + tail.size == 8) {
      // "::" must stand for at least one zero group.
      return null
    }

    val headGroups = head.map { parseGroup(it) ?: return null }
    val tailGroups = tail.map { parseGroup(it) ?: return null }

    val groups = IntArray(8)
    headGroups.forEachIndexed { i, g -> groups[i] = g }
    tailGroups.forEachIndexed { i, g -> groups[8 - tailGroups.size + i] = g }

    val out = ByteArray(16)
    for (i in 0 until 8) {
      out[i * 2] = ((groups[i] shr 8) and 0xff).toByte()
      out[i * 2 + 1] = (groups[i] and 0xff).toByte()
    }
    return out
  }

  private fun parseGroup(group: String): Int? {
    if (group.isEmpty() || group.length > 4) return null
    var value = 0
    for (c in group) {
      val digit =
          when (c) {
            in '0'..'9' -> c - '0'
            in 'a'..'f' -> c - 'a' + 10
            else -> return null
          }
      value = (value shl 4) or digit
    }
    return value
  }
}
