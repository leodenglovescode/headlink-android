// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.viewModel

import com.tailscale.ipn.ui.model.Ipn
import com.tailscale.ipn.ui.notifier.Notifier
import com.tailscale.ipn.ui.util.set
import com.tailscale.ipn.ui.view.ErrorDialogType
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Server setup for Headlink.
 *
 * Upstream splits this across three screens — an "alternate server" menu, a control-URL screen and
 * a separate auth-key screen — because the common case there is logging in to Tailscale's own
 * coordination server. Headlink only ever talks to a self-hosted Headscale, so the server address
 * is the *primary* setup step, not an alternative to anything.
 *
 * The backend already accepts both values in a single call: [IpnViewModel.login] takes masked prefs
 * (carrying ControlURL) and an auth key together. So one screen is not a shortcut around the
 * machinery, it is a straighter path through it.
 */
class HeadscaleLoginViewModel : IpnViewModel() {

  val errorDialog: StateFlow<ErrorDialogType?> = MutableStateFlow(null)

  /** The currently configured server, so the field opens pre-filled rather than blank. */
  fun currentControlUrl(): String = Notifier.prefs.value?.ControlURL?.trim().orEmpty()

  /**
   * Applies the server URL and, if given, the auth key, then starts login.
   *
   * An empty auth key is not an error: it means interactive registration, where Headscale shows a
   * page with the `headscale nodes register` command to run.
   */
  fun connect(serverUrl: String, authKey: String, onSuccess: () -> Unit) {
    val url = serverUrl.trim()
    if (!isPlausibleUrl(url)) {
      errorDialog.set(ErrorDialogType.INVALID_CUSTOM_URL)
      return
    }

    val prefs = Ipn.MaskedPrefs()
    prefs.ControlURL = url
    // Headscale deployments generally do not run MagicDNS, and inheriting the coordination
    // server's DNS settings on a self-hosted setup tends to break name resolution rather than
    // improve it. Off by default; still switchable under Settings -> DNS.
    prefs.CorpDNS = false

    val key = authKey.trim().ifEmpty { null }
    if (key != null) {
      prefs.WantRunning = true
    }

    login(prefs, authKey = key) { result ->
      result
          .onFailure { errorDialog.set(ErrorDialogType.ADD_PROFILE_FAILED) }
          .onSuccess { onSuccess() }
    }
  }

  /** Whether a server is currently configured, which is what makes logging out meaningful. */
  fun isLoggedIn(): Boolean = loggedInUser.value?.ID?.isNotEmpty() == true

  /**
   * A deliberately loose check.
   *
   * The underlying local API silently falls back to the default server on a malformed URL, so the
   * point is to catch obvious typos, not to be a URL validator. An IP-literal host is accepted: it
   * is legitimate on a LAN with a certificate carrying a matching IP SAN.
   */
  private fun isPlausibleUrl(url: String): Boolean =
      url.startsWith("http", ignoreCase = true) && url.contains("://") && url.length > 8
}
