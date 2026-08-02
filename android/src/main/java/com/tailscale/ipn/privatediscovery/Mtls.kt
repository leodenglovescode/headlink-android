// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.privatediscovery

import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Mutual-TLS support for the lookup request, and *only* for the lookup request.
 *
 * Some deployments protect the lookup endpoint with a client certificate in addition to the shared
 * secret — the endpoint this feature was written against does exactly that, refusing the connection
 * outright when no client certificate is presented.
 *
 * Everything here strengthens the lookup connection; nothing weakens it:
 * * A client certificate is *presented*, which is purely additive.
 * * An optional extra CA is *added* to the trust anchors, never substituted for the system ones, so
 *   publicly trusted endpoints keep verifying exactly as before.
 * * Hostname verification is untouched — `HttpsURLConnection` still performs it.
 * * There is deliberately no "trust everything" path anywhere in this file. A missing or unusable
 *   certificate produces a clean failure, never a downgrade.
 *
 * The [javax.net.ssl.SSLSocketFactory] built here is installed on the single lookup connection. The
 * coordination-server connection is made by the Tailscale core and never sees any of this.
 *
 * This file is free of Android imports so the whole of it is exercised by JVM unit tests, including
 * a real handshake against a listener that requires client authentication.
 */
object Mtls {

  /** A human-readable summary of a loaded client certificate. Contains no key material. */
  data class Identity(
      val subject: String,
      val issuer: String,
      val notAfterEpochMillis: Long,
  ) {
    fun isExpired(nowMillis: Long): Boolean = nowMillis > notAfterEpochMillis
  }

  /** Why a certificate bundle could not be used. Never carries the passphrase. */
  enum class Problem {
    /** The bytes are not a PKCS#12 bundle, or the passphrase is wrong — these are not separable. */
    UNREADABLE,
    /** Parsed, but contains no private key entry, so it cannot be used as a client identity. */
    NO_PRIVATE_KEY,
    /** The supplied CA material could not be parsed as one or more X.509 certificates. */
    BAD_CA,
  }

  class MtlsException(val problem: Problem, message: String) : Exception(message)

  /**
   * Builds a socket factory that presents [p12] as the client identity and trusts the system CAs
   * plus any certificates in [extraCaPem].
   *
   * Returns null when neither a client certificate nor an extra CA is configured, meaning the
   * caller should use the platform default and behave exactly as before.
   *
   * @throws MtlsException if configured material is present but unusable. Failing loudly matters
   *   here: silently falling back to the default factory would turn "my certificate is broken" into
   *   an indefinite, unexplained connection failure.
   */
  @Throws(MtlsException::class)
  fun socketFactory(
      p12: ByteArray?,
      passphrase: String,
      extraCaPem: String?,
  ): SSLSocketFactory? {
    val hasClientCert = p12 != null && p12.isNotEmpty()
    val hasExtraCa = !extraCaPem.isNullOrBlank()
    if (!hasClientCert && !hasExtraCa) return null

    val keyManagers = if (hasClientCert) keyManagers(p12!!, passphrase) else null
    val trustManagers = if (hasExtraCa) arrayOf<TrustManager>(trustManager(extraCaPem!!)) else null

    val context = SSLContext.getInstance("TLS")
    // Nulls mean "platform default" for that half, which is what we want when only one of the two
    // is configured.
    context.init(keyManagers, trustManagers, SecureRandom())
    return context.socketFactory
  }

  /**
   * Summarises the client certificate in [p12], for display in settings.
   *
   * @throws MtlsException if the bundle cannot be read.
   */
  @Throws(MtlsException::class)
  fun describe(p12: ByteArray, passphrase: String): Identity {
    val store = loadPkcs12(p12, passphrase)
    val alias =
        store.aliases().toList().firstOrNull { store.isKeyEntry(it) }
            ?: throw MtlsException(
                Problem.NO_PRIVATE_KEY, "The certificate bundle contains no private key")
    val cert =
        store.getCertificate(alias) as? X509Certificate
            ?: throw MtlsException(
                Problem.NO_PRIVATE_KEY, "The certificate bundle contains no usable certificate")
    return Identity(
        subject = cert.subjectX500Principal.name,
        issuer = cert.issuerX500Principal.name,
        notAfterEpochMillis = cert.notAfter.time)
  }

  private fun keyManagers(p12: ByteArray, passphrase: String): Array<KeyManager> {
    val store = loadPkcs12(p12, passphrase)
    if (store.aliases().toList().none { store.isKeyEntry(it) }) {
      throw MtlsException(Problem.NO_PRIVATE_KEY, "The certificate bundle contains no private key")
    }
    val factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    try {
      factory.init(store, passphrase.toCharArray())
    } catch (e: Exception) {
      // Deliberately not echoing e.message: key-material errors can quote alias and key details.
      throw MtlsException(Problem.UNREADABLE, "The client certificate could not be loaded")
    }
    return factory.keyManagers
  }

  private fun loadPkcs12(p12: ByteArray, passphrase: String): KeyStore {
    return try {
      KeyStore.getInstance("PKCS12").apply {
        load(ByteArrayInputStream(p12), passphrase.toCharArray())
      }
    } catch (e: Exception) {
      // A wrong passphrase and a corrupt file are indistinguishable here, and saying so is honest:
      // reporting "wrong passphrase" for a corrupt file would send the user down a blind alley.
      throw MtlsException(
          Problem.UNREADABLE, "Could not read the certificate bundle; check the passphrase")
    }
  }

  /**
   * A trust manager accepting anything the platform accepts, *plus* anything signed by the supplied
   * CA.
   *
   * Additive by construction: the platform manager is consulted first and its verdict is enough on
   * its own, so an endpoint with a publicly trusted certificate is validated exactly as it would be
   * without this feature. Only when the platform rejects the chain does the extra anchor get a say,
   * and if it also rejects, the original platform error is what propagates.
   */
  internal fun trustManager(caPem: String): X509TrustManager {
    val extra = fromCertificates(caPem)
    val platform = defaultTrustManager()
    return object : X509TrustManager {
      override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
          platform.checkClientTrusted(chain, authType)

      override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        try {
          platform.checkServerTrusted(chain, authType)
        } catch (platformFailure: CertificateException) {
          try {
            extra.checkServerTrusted(chain, authType)
          } catch (extraFailure: CertificateException) {
            // Surface the platform's reason: it is the one that applies to the common case.
            throw platformFailure
          }
        }
      }

      override fun getAcceptedIssuers(): Array<X509Certificate> =
          platform.acceptedIssuers + extra.acceptedIssuers
    }
  }

  /** Builds a trust manager over the certificates in [pem], which may hold several. */
  private fun fromCertificates(pem: String): X509TrustManager {
    val certificates =
        try {
          java.security.cert.CertificateFactory.getInstance("X.509")
              .generateCertificates(ByteArrayInputStream(pem.toByteArray(Charsets.UTF_8)))
        } catch (e: Exception) {
          throw MtlsException(Problem.BAD_CA, "Could not read the CA certificate")
        }
    if (certificates.isEmpty()) {
      throw MtlsException(Problem.BAD_CA, "No certificates found in the CA file")
    }
    val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
    certificates.forEachIndexed { i, certificate -> store.setCertificateEntry("ca$i", certificate) }
    return firstX509(
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
          init(store)
        })
  }

  private fun defaultTrustManager(): X509TrustManager =
      firstX509(
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            // null means "the platform's own trust anchors".
            init(null as KeyStore?)
          })

  private fun firstX509(factory: TrustManagerFactory): X509TrustManager =
      factory.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
          ?: throw MtlsException(Problem.BAD_CA, "No usable trust manager available")
}
