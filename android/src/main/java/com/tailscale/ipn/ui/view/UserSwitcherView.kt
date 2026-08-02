// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.R
import com.tailscale.ipn.ui.util.Lists
import com.tailscale.ipn.ui.util.itemsWithDividers
import com.tailscale.ipn.ui.util.set
import com.tailscale.ipn.ui.viewModel.UserSwitcherViewModel

data class UserSwitcherNav(
    val backToSettings: BackNavigation,
    val onNavigateHome: () -> Unit,
    val onNavigateToServerSetup: () -> Unit
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UserSwitcherView(nav: UserSwitcherNav, viewModel: UserSwitcherViewModel = viewModel()) {
  val users by viewModel.loginProfiles.collectAsState()
  val currentUser by viewModel.loggedInUser.collectAsState()
  val showHeaderMenu by viewModel.showHeaderMenu.collectAsState()
  val context = LocalContext.current
  val netmapState by viewModel.netmap.collectAsState()
  val capabilityIsOwner = "https://tailscale.com/cap/is-owner"

  Scaffold(
      topBar = {
        Header(
            R.string.accounts,
            onBack = nav.backToSettings,
            actions = {
              Row {
                FusMenu(viewModel = viewModel, onServerSetupClick = nav.onNavigateToServerSetup)
                IconButton(onClick = { viewModel.showHeaderMenu.set(!showHeaderMenu) }) {
                  Icon(Icons.Default.MoreVert, "menu")
                }
              }
            })
      }) { innerPadding ->
        Column(
            modifier = Modifier.padding(innerPadding).fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
              val showErrorDialog by viewModel.errorDialog.collectAsState()

              // Show the error overlay if need be
              showErrorDialog?.let {
                ErrorDialog(type = it, action = { viewModel.errorDialog.set(null) })
              }

              // When switch is invoked, this stores the ID of the user we're trying to switch to
              // so we can decorate it with a spinner.  The actual logged in user will not change
              // until
              // we get our first netmap update back with the new userId for SelfNode.
              // (jonathan) TODO: This user switch is not immediate.  We may need to represent the
              // "switching users" state globally (if ipnState is insufficient)
              val nextUserId = remember { mutableStateOf<String?>(null) }

              LazyColumn {
                itemsWithDividers(users ?: emptyList()) { user ->
                  if (user.ID == currentUser?.ID) {
                    UserView(profile = user, actionState = UserActionState.CURRENT)
                  } else {
                    val state =
                        if (user.ID == nextUserId.value) UserActionState.SWITCHING
                        else UserActionState.NONE
                    UserView(
                        profile = user,
                        actionState = state,
                        onClick = {
                          nextUserId.value = user.ID
                          viewModel.switchProfile(user) {
                            if (it.isFailure) {
                              viewModel.errorDialog.set(ErrorDialogType.LOGOUT_FAILED)
                              nextUserId.value = null
                            } else {
                              nav.onNavigateHome()
                            }
                          }
                        })
                  }
                }

                item {
                  Lists.SectionDivider()
                  Setting.Text(R.string.add_account) { nav.onNavigateToServerSetup() }

                  Lists.ItemDivider()
                  Setting.Text(R.string.reauthenticate) { viewModel.login() }

                  if (currentUser != null) {
                    Lists.ItemDivider()
                    Setting.Text(
                        R.string.log_out,
                        destructive = true,
                        onClick = {
                          viewModel.logout {
                            it.onSuccess { nav.onNavigateHome() }
                                .onFailure {
                                  viewModel.errorDialog.set(ErrorDialogType.LOGOUT_FAILED)
                                }
                          }
                        })
                  }
                }
              }
            }
      }
}

@Composable
fun FusMenu(onServerSetupClick: () -> Unit, viewModel: UserSwitcherViewModel) {
  val expanded by viewModel.showHeaderMenu.collectAsState()

  DropdownMenu(
      expanded = expanded,
      onDismissRequest = { viewModel.showHeaderMenu.set(false) },
      modifier = Modifier.background(MaterialTheme.colorScheme.surfaceContainer)) {
        // Headlink talks to one self-hosted Headscale, so there is a single entry point here
        // rather than upstream's "alternate server" plus separate auth-key screens.
        MenuItem(
            onClick = {
              onServerSetupClick()
              viewModel.showHeaderMenu.set(false)
            },
            text = stringResource(id = R.string.headscale_change_server))
      }
}

@Composable
fun MenuItem(text: String, onClick: () -> Unit) {
  DropdownMenuItem(
      modifier = Modifier.padding(horizontal = 8.dp, vertical = 0.dp),
      onClick = onClick,
      text = { Text(text = text) })
}

@Composable
@Preview
fun UserSwitcherViewPreview() {
  val vm = UserSwitcherViewModel()
  val nav = UserSwitcherNav(backToSettings = {}, onNavigateHome = {}, onNavigateToServerSetup = {})
  UserSwitcherView(nav, vm)
}
