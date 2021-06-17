package io.netty.util.internal.resources.openssl;

import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.ssl.*;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SelfSignedCertificate;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;

/** SSLContext factory for handle client connection */
public final class SSLContextFactory {

  private SSLContextFactory() {}

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
        .build();
  }

  public static SslContext generateServerSslContext() throws CertificateException, SSLException {
    SelfSignedCertificate ssc = new SelfSignedCertificate();
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

  public static SslContext generateDTLSContext(
      InputStream caPath,
      InputStream certificatePath,
      InputStream privateKeyPath,
      String keyPassword)
      throws SSLException {
    SslContext sslCtx =
        SslContextBuilder.forServer(certificatePath, privateKeyPath, keyPassword)
            .sslProvider(SslProvider.OPENSSL)
            .protocols("DTLSv1.2")
            .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
            .trustManager(caPath)
            .build();
    return sslCtx;
  }
}
