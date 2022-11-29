package io.netty.util.internal.cert.jsse;

import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

/**
 * SSLContext factory for handle client connection
 */
public final class SSLContextFactory {

  private SSLContextFactory() {
  }

  public static SslContext generateServerSslContext(
      InputStream caPath,
      InputStream certificatePath,
      InputStream privateKeyPath,
      String keyPassword)
      throws SSLException {
    return SslContextBuilder.forServer(certificatePath, privateKeyPath, keyPassword)
        .sslProvider(SslProvider.OPENSSL)
        .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
        .trustManager(caPath)
        .applicationProtocolConfig(
            new ApplicationProtocolConfig(
                ApplicationProtocolConfig.Protocol.ALPN,
                ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                ApplicationProtocolNames.HTTP_2,
                ApplicationProtocolNames.HTTP_1_1))
        .build();
  }

  public static SslContext generateServerSslContext() throws CertificateException, SSLException {
    var ssc = new SelfSignedCertificate();
    return SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey())
        .sslProvider(SslProvider.JDK)
        .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
        .applicationProtocolConfig(
            new ApplicationProtocolConfig(
                ApplicationProtocolConfig.Protocol.ALPN,
                ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                ApplicationProtocolNames.HTTP_2,
                ApplicationProtocolNames.HTTP_1_1))
        .build();
  }

  public static SslContext generateClientSslContext(
      InputStream caPath,
      InputStream certificatePath,
      InputStream privateKeyPath,
      String keyPassword)
      throws IOException {
    return SslContextBuilder.forClient()
        .sslProvider(SslProvider.OPENSSL)
        .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
        .trustManager(caPath)
        .keyManager(certificatePath, privateKeyPath, keyPassword)
        .applicationProtocolConfig(
            new ApplicationProtocolConfig(
                ApplicationProtocolConfig.Protocol.ALPN,
                ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                ApplicationProtocolNames.HTTP_2,
                ApplicationProtocolNames.HTTP_1_1))
        .build();
  }

  public static SslContext generateClientSslContext() throws SSLException {
    return SslContextBuilder.forClient()
        .sslProvider(SslProvider.JDK)
        .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
        .trustManager(InsecureTrustManagerFactory.INSTANCE)
        .applicationProtocolConfig(
            new ApplicationProtocolConfig(
                ApplicationProtocolConfig.Protocol.ALPN,
                ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                ApplicationProtocolNames.HTTP_2,
                ApplicationProtocolNames.HTTP_1_1))
        .build();
  }

  public static SSLContext generateDTLSContext(
      InputStream caPath,
      InputStream certificatePath,
      InputStream privateKeyPath,
      String keyPassword)
      throws SSLException {
    try {
      var sslCtx = SSLContext.getInstance("DTLSv1.2");
      Collection<X509Certificate> ca =
          PemUtils.readCertificatesStream(Collections.singleton(caPath));
      var privateKey = PemUtils.readPrivateKeyStream(privateKeyPath, keyPassword::toCharArray);
      Collection<X509Certificate> cer =
          PemUtils.readCertificatesStream(Collections.singleton(certificatePath));
      var ks = KeyStoreUtil.buildKeyStore(cer, privateKey, keyPassword.toCharArray());
      var ts = KeyStoreUtil.buildTrustStore(ca);
      var kmf = KeyManagerFactory.getInstance("SunX509");
      kmf.init(ks, keyPassword.toCharArray());
      var tmf = TrustManagerFactory.getInstance("SunX509");
      tmf.init(ts);
      sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
      return sslCtx;
    } catch (GeneralSecurityException e) {
      throw new SSLException("error occur while generate dtls context", e);
    }
  }

  public static SslStream generateDTLSStream(
      InputStream caPath,
      InputStream certificatePath,
      InputStream privateKeyPath) {
    return new SslStream(caPath, certificatePath, privateKeyPath);
  }
}
