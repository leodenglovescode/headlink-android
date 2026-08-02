// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.R
import com.tailscale.ipn.privatediscovery.CacheAgeUnit
import com.tailscale.ipn.privatediscovery.PrivateDiscoveryPolicy
import com.tailscale.ipn.privatediscovery.ValidationError
import com.tailscale.ipn.ui.theme.listItem
import com.tailscale.ipn.ui.util.Lists
import com.tailscale.ipn.ui.viewModel.PrivateDiscoveryViewModel
import java.text.DateFormat
import java.util.Date

/**
 * Settings screen for Headlink's Private Headscale IPv6 Discovery.
 *
 * The secret field is masked by default and is only ever revealed by an explicit tap. The secret is
 * never rendered in the status area, in the result banner, or in any log line.
 */
@Composable
fun PrivateDiscoveryView(
    backToSettings: BackNavigation,
    model: PrivateDiscoveryViewModel = viewModel()
) {
  val enabled by model.enabled.collectAsState()
  val lookupUrl by model.lookupUrl.collectAsState()
  val authHeader by model.authHeader.collectAsState()
  val secret by model.secret.collectAsState()
  val secretVisible by model.secretVisible.collectAsState()
  val cacheAgeValue by model.cacheAgeValue.collectAsState()
  val cacheAgeUnit by model.cacheAgeUnit.collectAsState()
  val timeoutSeconds by model.timeoutSeconds.collectAsState()
  val urlError by model.urlError.collectAsState()
  val authHeaderError by model.authHeaderError.collectAsState()
  val cacheAgeError by model.cacheAgeError.collectAsState()
  val timeoutError by model.timeoutError.collectAsState()
  val cachedAddress by model.cachedAddress.collectAsState()
  val cachedAtMillis by model.cachedAtMillis.collectAsState()
  val cacheStatus by model.cacheStatus.collectAsState()
  val lastResult by model.lastResult.collectAsState()
  val busy by model.busy.collectAsState()
  val actionResult by model.actionResult.collectAsState()

  val clientCert by model.clientCert.collectAsState()
  val clientCertPassphrase by model.clientCertPassphrase.collectAsState()
  val clientCertPassphraseVisible by model.clientCertPassphraseVisible.collectAsState()
  val clientCertError by model.clientCertError.collectAsState()
  val extraCaSubject by model.extraCaSubject.collectAsState()
  val extraCaError by model.extraCaError.collectAsState()

  var showClearCacheDialog by remember { mutableStateOf(false) }

  // Certificate files are read through the document picker, so Headlink never needs storage
  // permissions and only ever sees the one file the user explicitly chose.
  val context = LocalContext.current
  val clientCertPicker =
      rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { model.onClientCertPicked(readAll(context, it)) }
      }
  val caPicker =
      rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { model.onExtraCaPicked(readAll(context, it)) }
      }

  Scaffold(topBar = { Header(R.string.private_discovery_title, onBack = backToSettings) }) {
      innerPadding ->
    Column(modifier = Modifier.padding(innerPadding).verticalScroll(rememberScrollState())) {
      Lists.MultilineDescription {
        Text(
            stringResource(R.string.private_discovery_description),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
      }

      Setting.Switch(
          R.string.private_discovery_enable,
          subtitle = stringResource(R.string.private_discovery_enable_subtitle),
          isOn = enabled,
          onToggle = { model.setEnabled(it) })

      // ------------------------------------------------------------ endpoint
      Lists.SectionDivider(stringResource(R.string.private_discovery_endpoint_header))

      TextFieldSetting(
          label = stringResource(R.string.private_discovery_lookup_url),
          value = lookupUrl,
          placeholder = stringResource(R.string.private_discovery_lookup_url_placeholder),
          error = urlError?.let { stringResource(urlErrorText(it)) },
          keyboardType = KeyboardType.Uri,
          onValueChange = { model.setLookupUrl(it) })

      Lists.ItemDivider()

      TextFieldSetting(
          label = stringResource(R.string.private_discovery_auth_header),
          value = authHeader,
          placeholder = stringResource(R.string.private_discovery_auth_header_placeholder),
          error =
              authHeaderError?.let {
                stringResource(R.string.private_discovery_error_auth_header_invalid)
              },
          supporting = stringResource(R.string.private_discovery_auth_header_supporting),
          keyboardType = KeyboardType.Text,
          onValueChange = { model.setAuthHeader(it) })

      Lists.ItemDivider()

      TextFieldSetting(
          label = stringResource(R.string.private_discovery_secret),
          value = secret,
          placeholder = stringResource(R.string.private_discovery_secret_placeholder),
          error = null,
          supporting = stringResource(R.string.private_discovery_secret_stored),
          keyboardType = KeyboardType.Password,
          // Masked unless the user explicitly asks to see it.
          visualTransformation =
              if (secretVisible) VisualTransformation.None else PasswordVisualTransformation(),
          trailing = {
            TextButton(onClick = { model.toggleSecretVisible() }) {
              Text(
                  stringResource(
                      if (secretVisible) R.string.private_discovery_hide_secret
                      else R.string.private_discovery_show_secret))
            }
          },
          onValueChange = { model.setSecret(it) })

      // ---------------------------------------------------------- mutual TLS
      Lists.SectionDivider(stringResource(R.string.private_discovery_mtls_header))

      Lists.MultilineDescription {
        Text(
            stringResource(R.string.private_discovery_mtls_description),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
      }

      StatusRow(
          label = stringResource(R.string.private_discovery_client_cert),
          value =
              clientCert?.let {
                stringResource(
                    R.string.private_discovery_client_cert_summary,
                    it.subject,
                    formatTimestamp(it.notAfterEpochMillis))
              } ?: stringResource(R.string.private_discovery_none))

      clientCertError?.let {
        ListItem(
            colors = MaterialTheme.colorScheme.listItem,
            headlineContent = {
              Text(
                  it,
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.error)
            })
      }

      TextFieldSetting(
          label = stringResource(R.string.private_discovery_client_cert_passphrase),
          value = clientCertPassphrase,
          placeholder = stringResource(R.string.private_discovery_client_cert_passphrase_hint),
          error = null,
          keyboardType = KeyboardType.Password,
          visualTransformation =
              if (clientCertPassphraseVisible) VisualTransformation.None
              else PasswordVisualTransformation(),
          trailing = {
            TextButton(onClick = { model.toggleClientCertPassphraseVisible() }) {
              Text(
                  stringResource(
                      if (clientCertPassphraseVisible) R.string.private_discovery_hide_secret
                      else R.string.private_discovery_show_secret))
            }
          },
          onValueChange = { model.setClientCertPassphrase(it) })

      Row(
          modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
          horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                modifier = Modifier.weight(1f),
                onClick = { clientCertPicker.launch(arrayOf("*/*")) }) {
                  Text(stringResource(R.string.private_discovery_import_client_cert))
                }
            if (clientCert != null) {
              OutlinedButton(
                  modifier = Modifier.weight(1f), onClick = { model.removeClientCert() }) {
                    Text(
                        stringResource(R.string.private_discovery_remove),
                        color = MaterialTheme.colorScheme.error)
                  }
            }
          }

      Lists.ItemDivider()

      StatusRow(
          label = stringResource(R.string.private_discovery_extra_ca),
          value = extraCaSubject ?: stringResource(R.string.private_discovery_none))

      extraCaError?.let {
        ListItem(
            colors = MaterialTheme.colorScheme.listItem,
            headlineContent = {
              Text(
                  it,
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.error)
            })
      }

      Row(
          modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
          horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                modifier = Modifier.weight(1f), onClick = { caPicker.launch(arrayOf("*/*")) }) {
                  Text(stringResource(R.string.private_discovery_import_ca))
                }
            if (extraCaSubject != null) {
              OutlinedButton(modifier = Modifier.weight(1f), onClick = { model.removeExtraCa() }) {
                Text(
                    stringResource(R.string.private_discovery_remove),
                    color = MaterialTheme.colorScheme.error)
              }
            }
          }

      // -------------------------------------------------------------- timing
      Lists.SectionDivider(stringResource(R.string.private_discovery_timing_header))

      ListItem(
          colors = MaterialTheme.colorScheme.listItem,
          headlineContent = {
            Text(
                stringResource(R.string.private_discovery_cache_max_age),
                style = MaterialTheme.typography.bodyMedium)
          },
          supportingContent = {
            Column {
              Text(
                  stringResource(R.string.private_discovery_cache_max_age_subtitle),
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant)
              Row(
                  modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                  horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (cacheAgeUnit != CacheAgeUnit.ONLY_ON_FAILURE) {
                      OutlinedTextField(
                          modifier = Modifier.weight(1f),
                          value = cacheAgeValue,
                          onValueChange = { model.setCacheAgeValue(it) },
                          isError = cacheAgeError != null,
                          singleLine = true,
                          keyboardOptions =
                              KeyboardOptions(
                                  keyboardType = KeyboardType.Number, imeAction = ImeAction.Done))
                    }
                    CacheUnitSelector(
                        modifier = Modifier.weight(1f),
                        selected = cacheAgeUnit,
                        onSelected = { model.setCacheAgeUnit(it) })
                  }
              cacheAgeError?.let {
                Text(
                    stringResource(R.string.private_discovery_error_cache_age_range),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error)
              }
            }
          })

      Lists.ItemDivider()

      TextFieldSetting(
          label = stringResource(R.string.private_discovery_request_timeout),
          value = timeoutSeconds,
          placeholder = "10",
          error =
              timeoutError?.let { stringResource(R.string.private_discovery_error_timeout_range) },
          keyboardType = KeyboardType.Number,
          onValueChange = { model.setTimeoutSeconds(it) })

      // -------------------------------------------------------------- status
      Lists.SectionDivider(stringResource(R.string.private_discovery_status_header))

      StatusRow(
          label = stringResource(R.string.private_discovery_cached_address),
          value = cachedAddress ?: stringResource(R.string.private_discovery_none))

      Lists.ItemDivider()
      StatusRow(
          label = stringResource(R.string.private_discovery_last_lookup),
          value =
              cachedAtMillis?.let { formatTimestamp(it) }
                  ?: stringResource(R.string.private_discovery_none))

      Lists.ItemDivider()
      StatusRow(
          label = stringResource(R.string.private_discovery_cache_status),
          value = stringResource(cacheStatusText(cacheStatus)))

      Lists.ItemDivider()
      StatusRow(
          label = stringResource(R.string.private_discovery_last_result),
          value = lastResult ?: stringResource(R.string.private_discovery_none))

      // ------------------------------------------------------------- actions
      actionResult?.let { result ->
        ListItem(
            colors = MaterialTheme.colorScheme.listItem,
            headlineContent = {
              Text(
                  stringResource(
                      if (result.success) R.string.private_discovery_lookup_success
                      else R.string.private_discovery_lookup_failed),
                  style = MaterialTheme.typography.bodyMedium,
                  color =
                      if (result.success) MaterialTheme.colorScheme.onSurface
                      else MaterialTheme.colorScheme.error)
            },
            // For a success this is the discovered address, which the user explicitly asked to
            // see. It is never the token.
            supportingContent = { Text(result.detail, style = MaterialTheme.typography.bodySmall) })
      }

      Row(
          modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
          horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                modifier = Modifier.weight(1f), enabled = !busy, onClick = { model.testLookup() }) {
                  Text(
                      stringResource(
                          if (busy) R.string.private_discovery_working
                          else R.string.private_discovery_test_lookup))
                }
            Button(
                modifier = Modifier.weight(1f), enabled = !busy, onClick = { model.refreshNow() }) {
                  Text(stringResource(R.string.private_discovery_refresh_now))
                }
          }

      Lists.ItemDivider()
      Setting.Text(
          R.string.private_discovery_clear_cache,
          destructive = true,
          onClick = { showClearCacheDialog = true })
    }
  }

  if (showClearCacheDialog) {
    AlertDialog(
        onDismissRequest = { showClearCacheDialog = false },
        title = { Text(stringResource(R.string.private_discovery_clear_cache_confirm_title)) },
        text = { Text(stringResource(R.string.private_discovery_clear_cache_confirm_message)) },
        confirmButton = {
          TextButton(
              onClick = {
                showClearCacheDialog = false
                model.clearCache()
              }) {
                Text(
                    stringResource(R.string.private_discovery_clear_cache),
                    color = MaterialTheme.colorScheme.error)
              }
        },
        dismissButton = {
          TextButton(onClick = { showClearCacheDialog = false }) {
            Text(stringResource(R.string.cancel))
          }
        })
  }
}

@Composable
private fun TextFieldSetting(
    label: String,
    value: String,
    placeholder: String,
    error: String?,
    onValueChange: (String) -> Unit,
    supporting: String? = null,
    keyboardType: KeyboardType = KeyboardType.Text,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    trailing: (@Composable () -> Unit)? = null,
) {
  ListItem(
      colors = MaterialTheme.colorScheme.listItem,
      headlineContent = { Text(label, style = MaterialTheme.typography.bodyMedium) },
      supportingContent = {
        Column {
          OutlinedTextField(
              modifier = Modifier.fillMaxWidth(),
              value = value,
              onValueChange = onValueChange,
              placeholder = { Text(placeholder, style = MaterialTheme.typography.bodySmall) },
              isError = error != null,
              singleLine = true,
              visualTransformation = visualTransformation,
              trailingIcon = trailing,
              keyboardOptions =
                  KeyboardOptions(
                      capitalization = KeyboardCapitalization.None,
                      autoCorrectEnabled = false,
                      keyboardType = keyboardType,
                      imeAction = ImeAction.Done))
          error?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error)
          }
          if (error == null) {
            supporting?.let {
              Text(
                  it,
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
          }
        }
      })
}

@Composable
private fun CacheUnitSelector(
    modifier: Modifier = Modifier,
    selected: CacheAgeUnit,
    onSelected: (CacheAgeUnit) -> Unit
) {
  var expanded by remember { mutableStateOf(false) }
  Box(modifier = modifier) {
    OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = { expanded = true }) {
      Text(stringResource(cacheUnitText(selected)))
    }
    DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
      CacheAgeUnit.entries.forEach { unit ->
        DropdownMenuItem(
            text = { Text(stringResource(cacheUnitText(unit))) },
            onClick = {
              expanded = false
              onSelected(unit)
            })
      }
    }
  }
}

@Composable
private fun StatusRow(label: String, value: String) {
  ListItem(
      colors = MaterialTheme.colorScheme.listItem,
      headlineContent = { Text(label, style = MaterialTheme.typography.bodyMedium) },
      supportingContent = {
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
      })
}

private fun cacheUnitText(unit: CacheAgeUnit): Int =
    when (unit) {
      CacheAgeUnit.MINUTES -> R.string.private_discovery_unit_minutes
      CacheAgeUnit.HOURS -> R.string.private_discovery_unit_hours
      CacheAgeUnit.DAYS -> R.string.private_discovery_unit_days
      CacheAgeUnit.ONLY_ON_FAILURE -> R.string.private_discovery_unit_only_on_failure
    }

private fun cacheStatusText(status: PrivateDiscoveryPolicy.CacheStatus): Int =
    when (status) {
      PrivateDiscoveryPolicy.CacheStatus.VALID -> R.string.private_discovery_cache_valid
      PrivateDiscoveryPolicy.CacheStatus.EXPIRED -> R.string.private_discovery_cache_expired
      PrivateDiscoveryPolicy.CacheStatus.EMPTY -> R.string.private_discovery_cache_empty
    }

private fun urlErrorText(error: ValidationError): Int =
    when (error) {
      ValidationError.EMPTY -> R.string.private_discovery_error_url_empty
      ValidationError.NOT_HTTPS -> R.string.private_discovery_error_url_not_https
      ValidationError.NO_HOST -> R.string.private_discovery_error_url_no_host
      else -> R.string.private_discovery_error_url_invalid
    }

/**
 * Reads a picked document fully into memory.
 *
 * Certificate bundles are a few kilobytes, so this is bounded in practice; returning an empty array
 * on failure lets the caller report "unreadable" through the ordinary error path.
 */
private fun readAll(context: Context, uri: Uri): ByteArray =
    try {
      context.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: ByteArray(0)
    } catch (e: Exception) {
      ByteArray(0)
    }

private fun formatTimestamp(millis: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(millis))

@Preview
@Composable
fun PrivateDiscoveryViewPreview() {
  PrivateDiscoveryView(backToSettings = {})
}
