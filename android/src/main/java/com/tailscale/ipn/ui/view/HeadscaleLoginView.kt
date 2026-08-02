// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.R
import com.tailscale.ipn.ui.theme.listItem
import com.tailscale.ipn.ui.util.Lists
import com.tailscale.ipn.ui.util.set
import com.tailscale.ipn.ui.viewModel.HeadscaleLoginViewModel

/**
 * The single screen for pointing Headlink at a Headscale server.
 *
 * Server address and auth key live together because they are one decision, and because the backend
 * applies them in one call. Leaving the auth key blank falls back to interactive registration.
 */
@Composable
fun HeadscaleLoginView(
    onNavigateHome: BackNavigation,
    onBack: BackNavigation,
    model: HeadscaleLoginViewModel = viewModel()
) {
  val error by model.errorDialog.collectAsState()

  var serverUrl by remember { mutableStateOf(model.currentControlUrl().ifEmpty { "https://" }) }
  var authKey by remember { mutableStateOf("") }

  error?.let { ErrorDialog(type = it, action = { model.errorDialog.set(null) }) }

  val submit = { model.connect(serverUrl, authKey) { onNavigateHome() } }

  Scaffold(topBar = { Header(R.string.headscale_login_title, onBack = onBack) }) { innerPadding ->
    Column(modifier = Modifier.padding(innerPadding).verticalScroll(rememberScrollState())) {
      Lists.MultilineDescription {
        Text(
            stringResource(R.string.headscale_login_description),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
      }

      ListItem(
          colors = MaterialTheme.colorScheme.listItem,
          headlineContent = {
            Text(
                stringResource(R.string.headscale_server_url),
                style = MaterialTheme.typography.bodyMedium)
          },
          supportingContent = {
            Column {
              OutlinedTextField(
                  modifier = Modifier.fillMaxWidth(),
                  value = serverUrl,
                  onValueChange = { serverUrl = it },
                  singleLine = true,
                  placeholder = {
                    Text(
                        stringResource(R.string.headscale_server_url_placeholder),
                        style = MaterialTheme.typography.bodySmall)
                  },
                  keyboardOptions =
                      KeyboardOptions(
                          capitalization = KeyboardCapitalization.None,
                          autoCorrectEnabled = false,
                          keyboardType = KeyboardType.Uri,
                          imeAction = ImeAction.Next))
              Text(
                  stringResource(R.string.headscale_server_url_help),
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
          })

      Lists.ItemDivider()

      ListItem(
          colors = MaterialTheme.colorScheme.listItem,
          headlineContent = {
            Text(
                stringResource(R.string.headscale_auth_key),
                style = MaterialTheme.typography.bodyMedium)
          },
          supportingContent = {
            Column {
              OutlinedTextField(
                  modifier = Modifier.fillMaxWidth(),
                  value = authKey,
                  onValueChange = { authKey = it },
                  singleLine = true,
                  placeholder = {
                    Text(
                        stringResource(R.string.headscale_auth_key_placeholder),
                        style = MaterialTheme.typography.bodySmall)
                  },
                  keyboardOptions =
                      KeyboardOptions(
                          capitalization = KeyboardCapitalization.None,
                          autoCorrectEnabled = false,
                          imeAction = ImeAction.Go),
                  keyboardActions = KeyboardActions(onGo = { submit() }))
              Text(
                  stringResource(R.string.headscale_auth_key_help),
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
          })

      ListItem(
          colors = MaterialTheme.colorScheme.listItem,
          headlineContent = {
            Button(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                onClick = { submit() },
                content = { Text(stringResource(R.string.headscale_connect)) })
          })
    }
  }
}
