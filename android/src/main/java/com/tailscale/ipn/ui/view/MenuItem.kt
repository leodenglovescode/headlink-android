// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * A dropdown menu entry.
 *
 * Upstream declares this inside the account-switcher screen. Headlink has no accounts screen, so it
 * lives here instead — it is a plain shared widget with no connection to user profiles.
 */
@Composable
fun MenuItem(text: String, onClick: () -> Unit) {
  DropdownMenuItem(
      modifier = Modifier.padding(horizontal = 8.dp, vertical = 0.dp),
      onClick = onClick,
      text = { Text(text = text) })
}
