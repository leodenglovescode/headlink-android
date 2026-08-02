// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.privatediscovery

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.tailscale.ipn.util.TSLog
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Storage for the lookup shared secret. Abstracted so tests can substitute an in-memory store. */
interface TokenStore {
  fun load(): String

  fun save(token: String)

  fun clear()
}

/**
 * Stores the lookup shared secret encrypted under a non-exportable AES-256-GCM key held in the
 * Android Keystore.
 *
 * The key is generated on first use and never leaves the Keystore (hardware-backed, and on a Pixel
 * usually StrongBox-eligible hardware). Only the ciphertext — `Base64(iv || ciphertext||tag)` — is
 * written to SharedPreferences, so the on-disk value is useless without the device.
 *
 * This deliberately uses the platform Keystore directly rather than `EncryptedSharedPreferences`,
 * which Jetpack has since deprecated.
 *
 * No user authentication is required to use the key: the VPN service must be able to refresh the
 * coordination address while the screen is locked.
 */
class KeystoreTokenStore(
    context: Context,
    private val prefsName: String,
    private val prefKey: String
) : TokenStore {

  private val appContext = context.applicationContext

  private fun prefs(): SharedPreferences =
      appContext.getSharedPreferences(prefsName, Context.MODE_PRIVATE)

  override fun load(): String {
    val stored = prefs().getString(prefKey, null) ?: return ""
    if (stored.isEmpty()) return ""
    return try {
      val raw = Base64.decode(stored, Base64.NO_WRAP)
      if (raw.size <= IV_BYTES) return ""
      val iv = raw.copyOfRange(0, IV_BYTES)
      val ciphertext = raw.copyOfRange(IV_BYTES, raw.size)
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
      String(cipher.doFinal(ciphertext), Charsets.UTF_8)
    } catch (e: Exception) {
      // Never include the exception's contents: a crypto failure message can echo key material
      // details. A failure here just means "no usable token".
      TSLog.w(TAG, "stored secret could not be decrypted; treating it as unset")
      ""
    }
  }

  override fun save(token: String) {
    if (token.isEmpty()) {
      clear()
      return
    }
    try {
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(Cipher.ENCRYPT_MODE, secretKey())
      val ciphertext = cipher.doFinal(token.toByteArray(Charsets.UTF_8))
      val packed = cipher.iv + ciphertext
      prefs().edit().putString(prefKey, Base64.encodeToString(packed, Base64.NO_WRAP)).apply()
    } catch (e: Exception) {
      TSLog.e(TAG, "failed to store the secret securely")
    }
  }

  override fun clear() {
    prefs().edit().remove(prefKey).apply()
  }

  private fun secretKey(): SecretKey {
    val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    (keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let {
      return it.secretKey
    }
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    generator.init(
        KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // A fresh random IV per encryption; required for GCM safety.
            .setRandomizedEncryptionRequired(true)
            .build())
    return generator.generateKey()
  }

  companion object {
    private const val TAG = "PrivateDiscovery"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "headlink_private_discovery_token"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val IV_BYTES = 12
  }
}
