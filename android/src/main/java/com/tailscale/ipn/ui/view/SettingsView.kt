// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.BuildConfig
import com.tailscale.ipn.R
import com.tailscale.ipn.mdm.AlwaysNeverUserDecides
import com.tailscale.ipn.mdm.MDMSettings
import com.tailscale.ipn.mdm.ShowHide
import com.tailscale.ipn.privatediscovery.PrivateDiscovery
import com.tailscale.ipn.ui.theme.listItem
import com.tailscale.ipn.ui.util.AndroidTVUtil
import com.tailscale.ipn.ui.util.AndroidTVUtil.isAndroidTV
import com.tailscale.ipn.ui.util.AppVersion
import com.tailscale.ipn.ui.util.Lists
import com.tailscale.ipn.ui.util.set
import com.tailscale.ipn.ui.viewModel.AppViewModel
import com.tailscale.ipn.ui.viewModel.SettingsNav
import com.tailscale.ipn.ui.viewModel.SettingsViewModel

@Composable
fun SettingsView(
    settingsNav: SettingsNav,
    viewModel: SettingsViewModel = viewModel(),
    appViewModel: AppViewModel = viewModel()
) {

  val user by viewModel.loggedInUser.collectAsState()
  val managedByOrganization by viewModel.managedByOrganization.collectAsState()
  val tailnetLockEnabled by viewModel.tailNetLockEnabled.collectAsState()
  val corpDNSEnabled by viewModel.corpDNSEnabled.collectAsState()
  val isVPNPrepared by appViewModel.vpnPrepared.collectAsState()
  val showTailnetLock by MDMSettings.manageTailnetLock.flow.collectAsState()
  val useTailscaleSubnets by MDMSettings.useTailscaleSubnets.flow.collectAsState()
  val isPrivateDiscoveryEnabled = remember { PrivateDiscovery.config().enabled }

  Scaffold(
      topBar = {
        Header(titleRes = R.string.settings_title, onBack = settingsNav.onNavigateBackHome)
      }) { innerPadding ->
        Column(modifier = Modifier.padding(innerPadding).verticalScroll(rememberScrollState())) {
          // Headlink has no notion of accounts: there is one self-hosted Headscale server, and
          // this row is how you point at it or re-authenticate against it.
          Setting.Text(
              R.string.headscale_change_server, onClick = settingsNav.onNavigateToServerSetup)

          // Upstream shows a "manage your tailnet settings in the admin console"
          // link here, pointing at login.tailscale.com. Headlink talks to a
          // self-hosted Headscale server, which that page knows nothing about,
          // so the link could only send someone to a login screen for an
          // account they do not have. Headscale is administered from its own
          // CLI, so there is no URL to substitute.

          Lists.SectionDivider()
          Setting.Text(
              R.string.dns_settings,
              subtitle =
                  corpDNSEnabled?.let {
                    stringResource(
                        if (it) R.string.using_tailscale_dns else R.string.not_using_tailscale_dns)
                  },
              onClick = settingsNav.onNavigateToDNSSettings)

          Lists.ItemDivider()
          Setting.Text(
              R.string.split_tunneling,
              subtitle = stringResource(R.string.filter_apps_allowed_to_access_tailscale),
              onClick = settingsNav.onNavigateToSplitTunneling)

          if (showTailnetLock.value == ShowHide.Show) {
            Lists.ItemDivider()
            Setting.Text(
                R.string.tailnet_lock,
                subtitle =
                    tailnetLockEnabled?.let {
                      stringResource(if (it) R.string.enabled else R.string.disabled)
                    },
                onClick = settingsNav.onNavigateToTailnetLock)
          }
          if (useTailscaleSubnets.value == AlwaysNeverUserDecides.UserDecides) {
            Lists.ItemDivider()
            Setting.Text(R.string.subnet_routing, onClick = settingsNav.onNavigateToSubnetRouting)
          }

          // Headlink: Private Headscale IPv6 Discovery.
          Lists.SectionDivider()
          Setting.Text(
              R.string.private_discovery_title,
              subtitle =
                  stringResource(
                      if (isPrivateDiscoveryEnabled) R.string.private_discovery_settings_subtitle_on
                      else R.string.private_discovery_settings_subtitle_off),
              onClick = settingsNav.onNavigateToPrivateDiscovery)

          // The remote-client-logging switch is gone: Headlink uploads nothing,
          // so a control offering to turn uploads off could only mislead. The
          // guarantee is in libtailscale/notelemetry, not in a preference.

          if (!AndroidTVUtil.isAndroidTV()) {
            Lists.ItemDivider()
            Setting.Text(R.string.permissions, onClick = settingsNav.onNavigateToPermissions)
          }

          managedByOrganization.value?.let {
            Lists.ItemDivider()
            Setting.Text(
                title = stringResource(R.string.managed_by_orgName, it),
                onClick = settingsNav.onNavigateToManagedBy)
          }

          Lists.SectionDivider()
          Setting.Text(R.string.bug_report, onClick = settingsNav.onNavigateToBugReport)

          Lists.ItemDivider()
          Setting.Text(
              R.string.about_tailscale,
              subtitle = "${stringResource(id = R.string.version)} ${AppVersion.Short()}",
              onClick = settingsNav.onNavigateToAbout)

          // TODO: put a heading for the debug section
          if (BuildConfig.DEBUG) {
            Lists.SectionDivider()
            Lists.MutedHeader(text = stringResource(R.string.internal_debug_options))
            Setting.Text(R.string.mdm_settings, onClick = settingsNav.onNavigateToMDMSettings)
          }
        }
      }
}

object Setting {
  @Composable
  fun Text(
      titleRes: Int = 0,
      title: String? = null,
      subtitle: String? = null,
      destructive: Boolean = false,
      enabled: Boolean = true,
      onClick: (() -> Unit)? = null
  ) {
    var modifier: Modifier = Modifier
    if (enabled) {
      onClick?.let { modifier = modifier.clickable(onClick = it) }
    }
    ListItem(
        modifier = modifier,
        colors = MaterialTheme.colorScheme.listItem,
        headlineContent = {
          Text(
              title ?: stringResource(titleRes),
              style = MaterialTheme.typography.bodyMedium,
              color = if (destructive) MaterialTheme.colorScheme.error else Color.Unspecified)
        },
        supportingContent =
            subtitle?.let {
              {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
              }
            })
  }

  @Composable
  fun Switch(
      titleRes: Int = 0,
      title: String? = null,
      subtitle: String? = null,
      isOn: Boolean,
      enabled: Boolean = true,
      onToggle: (Boolean) -> Unit = {}
  ) {
    ListItem(
        colors = MaterialTheme.colorScheme.listItem,
        headlineContent = {
          Text(
              title ?: stringResource(titleRes),
              style = MaterialTheme.typography.bodyMedium,
          )
        },
        supportingContent =
            subtitle?.let {
              {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
              }
            },
        trailingContent = {
          TintedSwitch(checked = isOn, onCheckedChange = onToggle, enabled = enabled)
        })
  }
}

@Preview
@Composable
fun SettingsPreview() {
  val vm = SettingsViewModel()
  vm.corpDNSEnabled.set(true)
  vm.tailNetLockEnabled.set(true)
  vm.isAdmin.set(true)
  vm.managedByOrganization.set("Tails and Scales Inc.")
  SettingsView(SettingsNav({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}), vm)
}
