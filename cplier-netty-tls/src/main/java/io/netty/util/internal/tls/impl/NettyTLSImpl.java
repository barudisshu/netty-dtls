package io.netty.util.internal.tls.impl;

import io.netty.handler.ssl.SslHandler;
import io.netty.util.internal.dtls.adapter.JdkDtlsEngineAdapter;
import io.netty.util.internal.dtls.jsse.ClientDTLSHandler;
import io.netty.util.internal.dtls.jsse.HandshakeDTLSHandler;
import io.netty.util.internal.dtls.jsse.ServerDTLSHandler;
import io.netty.util.internal.tls.DTLSClientHandler;
import io.netty.util.internal.tls.DTLSHandler;
import io.netty.util.internal.tls.MultiplexingDTLSHandler;
import io.netty.util.internal.tls.NettyTLS;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;

import static org.osgi.service.component.annotations.ConfigurationPolicy.REQUIRE;

@Component(configurationPid = "io.netty.util.internal.tls", configurationPolicy = REQUIRE)
public class NettyTLSImpl implements NettyTLS {

  private final boolean insecure;

  private final SSLContext tlsSslContext;

  private final SSLContext dtlsSslContext;

  private final KeyManagerFactory kmf;

  private final TrustManagerFactory tmf;

  private final SSLParameters tlsParameters;

  private final SSLParameters dtlsParameters;

  @Activate
  public NettyTLSImpl(Config config) throws Exception {

    insecure = config.insecure();

    if (insecure) {
      tlsSslContext = null;
      dtlsSslContext = null;
      kmf = null;
      tmf = null;
      tlsParameters = null;
      dtlsParameters = null;
      return;
    }

    String tlsProtocol = config.tls_protocol();
    String dtlsProtocol = config.dtls_protocol();

    Provider jceProvider;
    Provider jsseProvider;

    switch (config.provider()) {
      case BOUNCYCASTLE:
        jceProvider = new BouncyCastleProvider();
        jsseProvider = new BouncyCastleJsseProvider(jceProvider);
        tlsSslContext = SSLContext.getInstance(tlsProtocol, jsseProvider);
        // TODO log this BouncyCastle complexity?
        dtlsSslContext = tlsSslContext;
        break;
      case JRE_DEFAULT:
        jceProvider = null;
        tlsSslContext = SSLContext.getInstance(tlsProtocol);
        dtlsSslContext = SSLContext.getInstance(dtlsProtocol);
        jsseProvider = tlsSslContext.getProvider();
        break;
      default:
        throw new IllegalArgumentException(
            "The configuration provider was not understood " + config.provider());
    }

    kmf = setupKeyManager(config, jceProvider, jsseProvider);

    tmf = setupTrustManager(config, jceProvider, jsseProvider);

    tlsSslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
    dtlsSslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

    tlsParameters = tlsSslContext.getDefaultSSLParameters();
    dtlsParameters = dtlsSslContext.getDefaultSSLParameters();

    switch (config.client_auth()) {
      case NEED:
        tlsParameters.setNeedClientAuth(true);
        dtlsParameters.setNeedClientAuth(true);
        break;
      case WANT:
        tlsParameters.setWantClientAuth(true);
        dtlsParameters.setWantClientAuth(true);
        break;
      case NONE:
        tlsParameters.setWantClientAuth(false);
        dtlsParameters.setWantClientAuth(false);
        break;
      default:
        break;
    }
  }

  private KeyManagerFactory setupKeyManager(
      Config config, Provider jceProvider, Provider jsseProvider)
      throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException,
          UnrecoverableKeyException {
    String keyManagerAlgorithm = config.key_manager_algorithm();

    if (keyManagerAlgorithm.isEmpty()) {
      keyManagerAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
    }

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(keyManagerAlgorithm, jsseProvider);

    KeyStore keyStore =
        jceProvider == null
            ? KeyStore.getInstance(config.keystore_type())
            : KeyStore.getInstance(config.keystore_type(), jceProvider);

    try (InputStream is = Files.newInputStream(new File(config.keystore_location()).toPath())) {
      keyStore.load(is, config._keystore_password().toCharArray());
    }

    String keystoreKeyPassword = config._keystore_key_password();

    kmf.init(
        keyStore,
        keystoreKeyPassword.isEmpty()
            ? config._keystore_password().toCharArray()
            : keystoreKeyPassword.toCharArray());
    return kmf;
  }

  private TrustManagerFactory setupTrustManager(
      Config config, Provider jceProvider, Provider jsseProvider)
      throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {

    String trustManagerAlgorithm = config.trust_manager_algorithm();

    if (trustManagerAlgorithm.isEmpty()) {
      trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
    }

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(trustManagerAlgorithm, jsseProvider);

    KeyStore trustStore =
        jceProvider == null
            ? KeyStore.getInstance(config.truststore_type())
            : KeyStore.getInstance(config.truststore_type(), jceProvider);
    try (InputStream is = Files.newInputStream(new File(config.truststore_location()).toPath())) {
      trustStore.load(is, config._truststore_password().toCharArray());
    }

    tmf.init(trustStore);

    return tmf;
  }

  @Override
  public MultiplexingDTLSHandler getDTLSHandler() {
    if (insecure) {
      return null;
    }
    return new HandshakeDTLSHandler(
        () -> {
          SSLEngine engine = dtlsSslContext.createSSLEngine();
          engine.setSSLParameters(dtlsParameters);
          return new JdkDtlsEngineAdapter(engine);
        });
  }

  @Override
  public DTLSClientHandler getDTLSClientHandler() {
    if (insecure) {
      return null;
    }
    SSLEngine engine = dtlsSslContext.createSSLEngine();
    engine.setSSLParameters(dtlsParameters);
    engine.setUseClientMode(true);

    return new ClientDTLSHandler(
        new JdkDtlsEngineAdapter(engine));
  }

  @Override
  public DTLSHandler getDTLSServerHandler() {
    if (insecure) {
      return null;
    }
    SSLEngine engine = dtlsSslContext.createSSLEngine();
    engine.setSSLParameters(dtlsParameters);
    engine.setUseClientMode(false);

    return new ServerDTLSHandler(
        new JdkDtlsEngineAdapter(engine));
  }

  @Override
  public SslHandler getTLSClientHandler() {
    if (insecure) {
      return null;
    }

    SSLEngine engine = tlsSslContext.createSSLEngine();
    engine.setSSLParameters(tlsParameters);
    engine.setUseClientMode(true);

    return new SslHandler(engine);
  }

  @Override
  public SslHandler getTLSServerHandler() {
    if (insecure) {
      return null;
    }

    SSLEngine engine = tlsSslContext.createSSLEngine();
    engine.setSSLParameters(tlsParameters);
    engine.setUseClientMode(false);

    return new SslHandler(engine);
  }

  @Override
  public boolean hasCertificate() {
    return kmf != null;
  }

  @Override
  public boolean hasTrust() {
    return tmf != null;
  }
}
