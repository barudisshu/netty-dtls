package io.netty.util.internal.cert.jsse;

import io.netty.util.internal.cert.exception.SslException;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Locale;
import java.util.function.Supplier;

/**
 * KeyStoreUtil for handle {@link SSLContext} storage facility
 *
 * @author galudisu
 */
final class KeyStoreUtil {

  private KeyStoreUtil() {
    throw new IllegalStateException("Utility class should not be instantiated");
  }

  static String inferKeyStoreType(Path path) {
    String name = path == null ? "" : path.toString().toLowerCase(Locale.ROOT);
    if (name.endsWith(".p12") || name.endsWith(".pfx") || name.endsWith(".pkcs12")) {
      return "PKCS12";
    } else {
      return "jks";
    }
  }

  static KeyStore readKeyStore(Path path, String type, char[] password)
      throws GeneralSecurityException {
    if (Files.notExists(path)) {
      throw new SslException(
          "cannot read a ["
              + type
              + "] keystore from ["
              + path.toAbsolutePath()
              + "] because the file does not exist");
    }
    try {
      KeyStore keyStore = KeyStore.getInstance(type);
      try (InputStream in = Files.newInputStream(path)) {
        keyStore.load(in, password);
      }
      return keyStore;
    } catch (IOException e) {
      throw new SslException(
          "cannot read a ["
              + type
              + "] keystore from ["
              + path.toAbsolutePath()
              + "] - "
              + e.getMessage(),
          e);
    }
  }

  /** Construct an in-memory keystore with a single key entry. */
  static KeyStore buildKeyStore(
      Collection<X509Certificate> certificateChain, PrivateKey privateKey, char[] password)
      throws GeneralSecurityException {
    KeyStore keyStore = buildNewKeyStore();
    keyStore.setKeyEntry(
        "mykey", privateKey, password, certificateChain.toArray(new Certificate[0]));
    return keyStore;
  }

  /** Construct an in-memory keystore with multiple trusted cert entries. */
  static KeyStore buildTrustStore(Iterable<X509Certificate> certificates)
      throws GeneralSecurityException {
    assert certificates != null : "Cannot create keystore with null certificates";
    KeyStore store = buildNewKeyStore();
    int counter = 0;
    for (Certificate certificate : certificates) {
      store.setCertificateEntry("cert-" + counter, certificate);
      counter++;
    }
    return store;
  }

  static KeyStore buildDefaultStore(
      Path keyStorePath, Supplier<char[]> passwordSupplier, String keyStoreType)
      throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance(keyStoreType);
    keyStore.load(
        (keyStorePath.getFileSystem().provider().newInputStream(keyStorePath)),
        passwordSupplier.get());
    return keyStore;
  }

  private static KeyStore buildNewKeyStore() throws GeneralSecurityException {
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    try {
      keyStore.load(null, null);
    } catch (IOException e) {
      throw new SslException("Unexpected error initializing a new in-memory keystore", e);
    }
    return keyStore;
  }

  /**
   * Creates a {@link X509ExtendedKeyManager} based on the key material in the provided {@link
   * KeyStore}
   */
  static X509ExtendedKeyManager createKeyManager(
      KeyStore keyStore, char[] password, String algorithm) throws GeneralSecurityException {
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
    kmf.init(keyStore, password);
    KeyManager[] keyManagers = kmf.getKeyManagers();
    for (KeyManager keyManager : keyManagers) {
      if (keyManager instanceof X509ExtendedKeyManager) {
        return (X509ExtendedKeyManager) keyManager;
      }
    }
    throw new SslException(
        "failed to find a X509ExtendedKeyManager in the key manager factory for ["
            + algorithm
            + "] and keystore ["
            + keyStore
            + "]");
  }

  /**
   * Creates a {@link X509ExtendedTrustManager} based on the trust material in the provided {@link
   * KeyStore}
   */
  static X509ExtendedTrustManager createTrustManager(KeyStore trustStore, String algorithm)
      throws NoSuchAlgorithmException, KeyStoreException {
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
    tmf.init(trustStore);
    TrustManager[] trustManagers = tmf.getTrustManagers();
    for (TrustManager trustManager : trustManagers) {
      if (trustManager instanceof X509ExtendedTrustManager) {
        return (X509ExtendedTrustManager) trustManager;
      }
    }
    throw new SslException(
        "failed to find a X509ExtendedTrustManager in the trust manager factory for ["
            + algorithm
            + "] and truststore ["
            + trustStore
            + "]");
  }
}
