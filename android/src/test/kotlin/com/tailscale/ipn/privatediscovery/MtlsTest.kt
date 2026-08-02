// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.privatediscovery

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URL
import java.security.KeyStore
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutual TLS for the lookup request, verified against a real TLS listener that requires client
 * authentication — the same thing the production endpoint does.
 *
 * Fixtures live in `src/test/resources/mtls/` and are throwaway keys; see the README there.
 */
class MtlsTest {

  private val passphrase = "testpass"

  private fun resource(name: String): ByteArray =
      javaClass.getResourceAsStream("/mtls/$name")?.use { it.readBytes() }
          ?: throw AssertionError("missing test fixture: $name")

  private fun caPem(): String = String(resource("ca.crt"), Charsets.UTF_8)

  /** A minimal HTTPS listener speaking just enough HTTP/1.1 to answer one request. */
  private class Listener(requireClientAuth: Boolean, caPem: ByteArray, serverP12: ByteArray) :
      AutoCloseable {
    val socket: SSLServerSocket
    val port: Int
    @Volatile var observedClientSubject: String? = null
    @Volatile var handshakeFailed = false
    private val ready = CountDownLatch(1)
    private val thread: Thread

    init {
      val keys =
          KeyStore.getInstance("PKCS12").apply {
            load(serverP12.inputStream(), "testpass".toCharArray())
          }
      val kmf =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(keys, "testpass".toCharArray())
          }
      val trust =
          KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            val ca =
                java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(caPem.inputStream())
            setCertificateEntry("ca", ca)
          }
      val tmf =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(trust)
          }
      val context =
          SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, tmf.trustManagers, SecureRandom())
          }
      socket = context.serverSocketFactory.createServerSocket(0) as SSLServerSocket
      socket.needClientAuth = requireClientAuth
      port = socket.localPort

      thread =
          Thread {
                ready.countDown()
                try {
                  while (!socket.isClosed) {
                    val client = socket.accept() as SSLSocket
                    try {
                      val reader = BufferedReader(InputStreamReader(client.inputStream))
                      // Consume the request head.
                      while (true) {
                        val line = reader.readLine() ?: break
                        if (line.isEmpty()) break
                      }
                      observedClientSubject =
                          client.session.peerCertificates
                              .filterIsInstance<java.security.cert.X509Certificate>()
                              .firstOrNull()
                              ?.subjectX500Principal
                              ?.name
                      val body = """{"ipv6": "2409:8a00:1234:5678::abcd"}"""
                      client.outputStream.write(
                          ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
                                  "Content-Length: ${body.length}\r\nConnection: close\r\n\r\n" +
                                  body)
                              .toByteArray())
                      client.outputStream.flush()
                    } catch (e: Exception) {
                      handshakeFailed = true
                    } finally {
                      runCatching { client.close() }
                    }
                  }
                } catch (e: Exception) {
                  // Listener closed; nothing to do.
                }
              }
              .apply {
                isDaemon = true
                start()
              }
      ready.await(5, TimeUnit.SECONDS)
    }

    override fun close() {
      runCatching { socket.close() }
      thread.interrupt()
    }
  }

  private fun listener(requireClientAuth: Boolean) =
      Listener(requireClientAuth, resource("ca.crt"), resource("server.p12"))

  /**
   * The whole point: a listener that refuses clients without a certificate accepts us when the
   * client certificate is configured.
   */
  @Test
  fun clientCertificateIsPresentedAndAccepted() {
    listener(requireClientAuth = true).use { server ->
      val factory =
          Mtls.socketFactory(
              p12 = resource("client.p12"), passphrase = passphrase, extraCaPem = caPem())
      assertNotNull(factory)

      val connection =
          URL("https://localhost:${server.port}/ip").openConnection() as HttpsURLConnection
      connection.sslSocketFactory = factory!!
      connection.connectTimeout = 10_000
      connection.readTimeout = 10_000

      assertEquals(200, connection.responseCode)
      val body = connection.inputStream.use { String(it.readBytes(), Charsets.UTF_8) }
      assertTrue(body.contains("2409:8a00:1234:5678::abcd"))
      connection.disconnect()

      assertTrue(
          "server should have seen our client certificate",
          server.observedClientSubject?.contains("headlink-test-client") == true)
    }
  }

  /**
   * Without a client certificate the same listener drops us. This reproduces the production symptom
   * that started all of this: the request goes out and the connection dies with no HTTP response at
   * all.
   */
  @Test
  fun withoutAClientCertificateTheConnectionIsRefused() {
    listener(requireClientAuth = true).use { server ->
      // Trust configured, but no client identity.
      val factory = Mtls.socketFactory(p12 = null, passphrase = "", extraCaPem = caPem())
      assertNotNull(factory)

      val connection =
          URL("https://localhost:${server.port}/ip").openConnection() as HttpsURLConnection
      connection.sslSocketFactory = factory!!
      connection.connectTimeout = 10_000
      connection.readTimeout = 10_000

      var failed = false
      try {
        connection.responseCode
      } catch (e: Exception) {
        failed = true
      }
      assertTrue("expected the handshake or request to fail without a client certificate", failed)
      connection.disconnect()
    }
  }

  /** Hostname verification is not disabled anywhere: a wrong hostname must still be rejected. */
  @Test
  fun hostnameVerificationStillApplies() {
    listener(requireClientAuth = false).use { server ->
      val factory =
          Mtls.socketFactory(
              p12 = resource("client.p12"), passphrase = passphrase, extraCaPem = caPem())
      // The fixture's SANs are localhost and 127.0.0.1; this name is neither.
      val connection =
          URL("https://127.0.0.2:${server.port}/ip").openConnection() as HttpsURLConnection
      connection.sslSocketFactory = factory!!
      connection.connectTimeout = 5_000
      connection.readTimeout = 5_000
      var failed = false
      try {
        connection.responseCode
      } catch (e: Exception) {
        failed = true
      }
      assertTrue("a certificate valid for another name must not be accepted", failed)
      connection.disconnect()
    }
  }

  /** With nothing configured the platform default is left completely alone. */
  @Test
  fun noMaterialMeansNoOverride() {
    assertNull(Mtls.socketFactory(p12 = null, passphrase = "", extraCaPem = null))
    assertNull(Mtls.socketFactory(p12 = ByteArray(0), passphrase = "", extraCaPem = ""))
  }

  /**
   * The extra CA is additive: the platform's own anchors are still present, so a publicly trusted
   * endpoint keeps validating exactly as it did before this feature existed.
   */
  @Test
  fun extraCaIsAddedToTheSystemAnchorsNotSubstitutedForThem() {
    val manager = Mtls.trustManager(caPem())
    val issuers = manager.acceptedIssuers.map { it.subjectX500Principal.name }
    assertTrue(
        "our test CA should be trusted", issuers.any { it.contains("Headlink Test Root CA") })
    assertTrue("the platform anchors must still be present, got ${issuers.size}", issuers.size > 1)
  }

  @Test
  fun describeReportsSubjectAndExpiryWithoutKeyMaterial() {
    val identity = Mtls.describe(resource("client.p12"), passphrase)
    assertTrue(identity.subject.contains("headlink-test-client"))
    assertTrue(identity.issuer.contains("Headlink Test Root CA"))
    assertTrue("fixture should not be expired", !identity.isExpired(System.currentTimeMillis()))
    assertFalse(identity.toString().contains(passphrase))
    assertFalse(identity.toString().contains("PRIVATE KEY"))
  }

  @Test
  fun wrongPassphraseFailsCleanlyAndNeverEchoesIt() {
    val secretish = "hunter2-not-the-real-passphrase"
    val e =
        try {
          Mtls.describe(resource("client.p12"), secretish)
          null
        } catch (thrown: Mtls.MtlsException) {
          thrown
        }
    assertNotNull("a wrong passphrase must be reported", e)
    assertEquals(Mtls.Problem.UNREADABLE, e!!.problem)
    assertFalse("the passphrase must never appear in the message", e.message!!.contains(secretish))
  }

  @Test
  fun garbageBundleIsRejected() {
    val e =
        try {
          Mtls.socketFactory("not a pkcs12 file".toByteArray(), passphrase, null)
          null
        } catch (thrown: Mtls.MtlsException) {
          thrown
        }
    assertNotNull(e)
    assertEquals(Mtls.Problem.UNREADABLE, e!!.problem)
  }

  @Test
  fun garbageCaIsRejected() {
    val e =
        try {
          Mtls.socketFactory(null, "", "-----BEGIN CERTIFICATE-----\nnonsense\n")
          null
        } catch (thrown: Mtls.MtlsException) {
          thrown
        }
    assertNotNull(e)
    assertEquals(Mtls.Problem.BAD_CA, e!!.problem)
  }

  /** The lookup Request renders without leaking either the secret or the bundle passphrase. */
  @Test
  fun requestRenderingRedactsEverySecret() {
    val request =
        PrivateDiscoveryLookup.Request(
            url = "https://lookup.example.com/ip?token=leaky",
            authHeader = "X-Sync-Secret",
            secret = "the-shared-secret",
            timeoutSeconds = 10,
            clientCertP12Base64 = "QkFTRTY0UDEy",
            clientCertPassphrase = "the-bundle-passphrase",
            extraCaPem = caPem())
    val rendered = request.toString()
    assertFalse(rendered.contains("the-shared-secret"))
    assertFalse(rendered.contains("the-bundle-passphrase"))
    assertFalse(rendered.contains("QkFTRTY0UDEy"))
    assertFalse(rendered.contains("leaky"))
    assertTrue(rendered.contains("clientCert=<present>"))
  }
}
