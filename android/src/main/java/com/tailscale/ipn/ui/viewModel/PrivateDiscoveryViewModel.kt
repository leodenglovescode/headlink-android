// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.viewModel

import android.util.Base64
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.tailscale.ipn.privatediscovery.CacheAgeUnit
import com.tailscale.ipn.privatediscovery.Mtls
import com.tailscale.ipn.privatediscovery.PrivateDiscovery
import com.tailscale.ipn.privatediscovery.PrivateDiscoveryLookup
import com.tailscale.ipn.privatediscovery.PrivateDiscoveryPolicy
import com.tailscale.ipn.privatediscovery.ValidationError
import com.tailscale.ipn.privatediscovery.validateAuthHeader
import com.tailscale.ipn.privatediscovery.validateCacheAgeValue
import com.tailscale.ipn.privatediscovery.validateLookupUrl
import com.tailscale.ipn.privatediscovery.validateTimeoutSeconds
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * View model for the Private Headscale IPv6 Discovery settings screen.
 *
 * Every field is persisted as soon as it validates, so settings survive navigating away or the app
 * being killed. The shared secret is written straight through to the Keystore-backed store and is
 * never held anywhere else.
 */
class PrivateDiscoveryViewModel : ViewModel() {

  /** Result banner for Test Lookup / Refresh Now. Never contains credentials. */
  data class ActionResult(val success: Boolean, val detail: String)

  private val _enabled = MutableStateFlow(false)
  val enabled: StateFlow<Boolean> = _enabled

  private val _lookupUrl = MutableStateFlow("")
  val lookupUrl: StateFlow<String> = _lookupUrl

  private val _authHeader = MutableStateFlow("")
  val authHeader: StateFlow<String> = _authHeader

  private val _secret = MutableStateFlow("")
  val secret: StateFlow<String> = _secret

  private val _secretVisible = MutableStateFlow(false)
  val secretVisible: StateFlow<Boolean> = _secretVisible

  // ---- mutual TLS -------------------------------------------------------

  /** Summary of the stored client certificate, or null when none is configured. */
  private val _clientCert = MutableStateFlow<Mtls.Identity?>(null)
  val clientCert: StateFlow<Mtls.Identity?> = _clientCert

  private val _clientCertPassphrase = MutableStateFlow("")
  val clientCertPassphrase: StateFlow<String> = _clientCertPassphrase

  private val _clientCertPassphraseVisible = MutableStateFlow(false)
  val clientCertPassphraseVisible: StateFlow<Boolean> = _clientCertPassphraseVisible

  /** Credential-free explanation of why the last import failed. */
  private val _clientCertError = MutableStateFlow<String?>(null)
  val clientCertError: StateFlow<String?> = _clientCertError

  private val _extraCaSubject = MutableStateFlow<String?>(null)
  val extraCaSubject: StateFlow<String?> = _extraCaSubject

  private val _extraCaError = MutableStateFlow<String?>(null)
  val extraCaError: StateFlow<String?> = _extraCaError

  /**
   * A bundle chosen from the file picker but not yet stored, because it has not been opened
   * successfully yet. Held only in memory, and dropped as soon as it is stored or replaced.
   */
  private var pendingP12: ByteArray? = null

  private val _cacheAgeValue = MutableStateFlow("")
  val cacheAgeValue: StateFlow<String> = _cacheAgeValue

  private val _cacheAgeUnit = MutableStateFlow(CacheAgeUnit.HOURS)
  val cacheAgeUnit: StateFlow<CacheAgeUnit> = _cacheAgeUnit

  private val _timeoutSeconds = MutableStateFlow("")
  val timeoutSeconds: StateFlow<String> = _timeoutSeconds

  private val _urlError = MutableStateFlow<ValidationError?>(null)
  val urlError: StateFlow<ValidationError?> = _urlError

  private val _authHeaderError = MutableStateFlow<ValidationError?>(null)
  val authHeaderError: StateFlow<ValidationError?> = _authHeaderError

  private val _cacheAgeError = MutableStateFlow<ValidationError?>(null)
  val cacheAgeError: StateFlow<ValidationError?> = _cacheAgeError

  private val _timeoutError = MutableStateFlow<ValidationError?>(null)
  val timeoutError: StateFlow<ValidationError?> = _timeoutError

  private val _cachedAddress = MutableStateFlow<String?>(null)
  val cachedAddress: StateFlow<String?> = _cachedAddress

  private val _cachedAtMillis = MutableStateFlow<Long?>(null)
  val cachedAtMillis: StateFlow<Long?> = _cachedAtMillis

  private val _cacheStatus = MutableStateFlow(PrivateDiscoveryPolicy.CacheStatus.EMPTY)
  val cacheStatus: StateFlow<PrivateDiscoveryPolicy.CacheStatus> = _cacheStatus

  private val _lastResult = MutableStateFlow<String?>(null)
  val lastResult: StateFlow<String?> = _lastResult

  private val _busy = MutableStateFlow(false)
  val busy: StateFlow<Boolean> = _busy

  private val _actionResult = MutableStateFlow<ActionResult?>(null)
  val actionResult: StateFlow<ActionResult?> = _actionResult

  init {
    load()
  }

  private fun load() {
    val config = PrivateDiscovery.config()
    _enabled.value = config.enabled
    _lookupUrl.value = config.lookupUrl
    _authHeader.value = config.authHeader
    _secret.value = config.secret
    _cacheAgeValue.value = config.cacheAgeValue.toString()
    _cacheAgeUnit.value = config.cacheAgeUnit
    _timeoutSeconds.value = config.timeoutSeconds.toString()
    _clientCertPassphrase.value = config.clientCertPassphrase
    _clientCert.value = describeStoredCert()
    _extraCaSubject.value = describeStoredCa()
    refreshStatus()
  }

  /** Reads back the stored bundle so settings show what is actually in effect. */
  private fun describeStoredCert(): Mtls.Identity? {
    val config = PrivateDiscovery.config()
    if (!config.hasClientCert()) return null
    return try {
      Mtls.describe(
          Base64.decode(config.clientCertP12Base64, Base64.NO_WRAP), config.clientCertPassphrase)
    } catch (e: Exception) {
      null
    }
  }

  private fun describeStoredCa(): String? {
    val pem = PrivateDiscovery.config().extraCaPem
    if (pem.isBlank()) return null
    return try {
      val certificate =
          java.security.cert.CertificateFactory.getInstance("X.509")
              .generateCertificate(pem.byteInputStream()) as java.security.cert.X509Certificate
      certificate.subjectX500Principal.name
    } catch (e: Exception) {
      null
    }
  }

  fun refreshStatus() {
    val config = PrivateDiscovery.config()
    val cache = PrivateDiscovery.cache()
    _cachedAddress.value = cache?.address
    _cachedAtMillis.value = cache?.fetchedAtEpochMillis
    _cacheStatus.value =
        PrivateDiscoveryPolicy.cacheStatus(config, cache, System.currentTimeMillis())
    _lastResult.value = PrivateDiscovery.lastResult()
  }

  fun setEnabled(value: Boolean) {
    _enabled.value = value
    PrivateDiscovery.setEnabled(value)
    refreshStatus()
  }

  fun setLookupUrl(value: String) {
    _lookupUrl.value = value
    val error = validateLookupUrl(value)
    _urlError.value = if (value.isBlank()) null else error
    // Persist the trimmed value whenever it is usable; a half-typed URL is simply not saved yet.
    if (error == null) PrivateDiscovery.setLookupUrl(value)
  }

  fun setAuthHeader(value: String) {
    _authHeader.value = value
    val error = validateAuthHeader(value)
    _authHeaderError.value = if (value.isBlank()) null else error
    if (error == null) PrivateDiscovery.setAuthHeader(value)
  }

  fun setSecret(value: String) {
    _secret.value = value
    PrivateDiscovery.setSecret(value)
  }

  fun toggleSecretVisible() {
    _secretVisible.value = !_secretVisible.value
  }

  fun toggleClientCertPassphraseVisible() {
    _clientCertPassphraseVisible.value = !_clientCertPassphraseVisible.value
  }

  /**
   * Accepts a PKCS#12 bundle chosen by the user.
   *
   * It is only persisted once it has actually been opened with the current passphrase, so a wrong
   * passphrase or a bad file can never leave unusable material in storage.
   */
  fun onClientCertPicked(bytes: ByteArray) {
    pendingP12 = bytes
    tryStoreClientCert()
  }

  fun setClientCertPassphrase(value: String) {
    _clientCertPassphrase.value = value
    tryStoreClientCert()
  }

  private fun tryStoreClientCert() {
    val bytes =
        pendingP12
            ?: PrivateDiscovery.config()
                .takeIf { it.hasClientCert() }
                ?.let {
                  try {
                    Base64.decode(it.clientCertP12Base64, Base64.NO_WRAP)
                  } catch (e: IllegalArgumentException) {
                    null
                  }
                }
            ?: return
    val passphrase = _clientCertPassphrase.value
    try {
      val identity = Mtls.describe(bytes, passphrase)
      PrivateDiscovery.setClientCert(Base64.encodeToString(bytes, Base64.NO_WRAP), passphrase)
      pendingP12 = null
      _clientCert.value = identity
      _clientCertError.value = null
    } catch (e: Mtls.MtlsException) {
      // e.message is credential-free by contract.
      _clientCertError.value = e.message
    }
  }

  fun removeClientCert() {
    pendingP12 = null
    _clientCertPassphrase.value = ""
    PrivateDiscovery.setClientCert("", "")
    _clientCert.value = null
    _clientCertError.value = null
  }

  /** Accepts a PEM CA certificate to trust in addition to the system anchors. */
  fun onExtraCaPicked(bytes: ByteArray) {
    val pem = String(bytes, Charsets.UTF_8)
    try {
      // Validate before storing, so an unusable file is rejected at import time rather than at
      // lookup time.
      Mtls.trustManager(pem)
      PrivateDiscovery.setExtraCaPem(pem)
      _extraCaSubject.value = describeStoredCa()
      _extraCaError.value = null
    } catch (e: Mtls.MtlsException) {
      _extraCaError.value = e.message
    }
  }

  fun removeExtraCa() {
    PrivateDiscovery.setExtraCaPem("")
    _extraCaSubject.value = null
    _extraCaError.value = null
  }

  fun setCacheAgeValue(value: String) {
    _cacheAgeValue.value = value
    val error = validateCacheAgeValue(value, _cacheAgeUnit.value)
    _cacheAgeError.value = error
    if (error == null) {
      value.trim().toIntOrNull()?.let { PrivateDiscovery.setCacheAge(it, _cacheAgeUnit.value) }
      refreshStatus()
    }
  }

  fun setCacheAgeUnit(unit: CacheAgeUnit) {
    _cacheAgeUnit.value = unit
    val error = validateCacheAgeValue(_cacheAgeValue.value, unit)
    _cacheAgeError.value = error
    val value = _cacheAgeValue.value.trim().toIntOrNull()
    if (unit == CacheAgeUnit.ONLY_ON_FAILURE) {
      PrivateDiscovery.setCacheAge(value ?: 1, unit)
    } else if (error == null && value != null) {
      PrivateDiscovery.setCacheAge(value, unit)
    }
    refreshStatus()
  }

  fun setTimeoutSeconds(value: String) {
    _timeoutSeconds.value = value
    val error = validateTimeoutSeconds(value)
    _timeoutError.value = error
    if (error == null) {
      value.trim().toIntOrNull()?.let { PrivateDiscovery.setTimeoutSeconds(it) }
    }
  }

  fun dismissActionResult() {
    _actionResult.value = null
  }

  /** Runs a lookup without touching the cache. */
  fun testLookup() = runLookup { PrivateDiscovery.testLookup() }

  /** Runs a lookup and, on success, replaces the cached address and timestamp. */
  fun refreshNow() = runLookup { PrivateDiscovery.refreshNow() }

  private fun runLookup(block: () -> PrivateDiscoveryLookup.LookupOutcome) {
    if (_busy.value) return
    _busy.value = true
    _actionResult.value = null
    viewModelScope.launch {
      val outcome = withContext(Dispatchers.IO) { block() }
      _actionResult.value =
          when (outcome) {
            is PrivateDiscoveryLookup.LookupOutcome.Success ->
                ActionResult(success = true, detail = outcome.address)
            is PrivateDiscoveryLookup.LookupOutcome.Failure ->
                ActionResult(success = false, detail = outcome.detail)
          }
      refreshStatus()
      _busy.value = false
    }
  }

  fun clearCache() {
    PrivateDiscovery.clearCache()
    _actionResult.value = null
    refreshStatus()
  }
}
