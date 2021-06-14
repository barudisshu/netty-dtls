package io.netty.util.internal.resources.openssl;

import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.ssl.*;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SelfSignedCertificate;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateException;

/** SSLContext factory for handle client connection */
public final class SSLContextFactory {

  private SSLContextFactory() {}

  public static SslContext generateServerSslContext(
      Path caPath, Path certificatePath, Path privateKeyPath, String keyPassword)
      throws SSLException {
    return SslContextBuilder.forServer(
            certificatePath.toFile(), privateKeyPath.toFile(), keyPassword)
        .sslProvider(SslProvider.OPENSSL)
        .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
        .trustManager(caPath.toFile())
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
      Path caPath, Path certificatePath, Path privateKeyPath, String keyPassword)
      throws IOException {
    return SslContextBuilder.forClient()
        .sslProvider(SslProvider.OPENSSL)
        .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
        .trustManager(caPath.toFile())
        .keyManager(certificatePath.toFile(), privateKeyPath.toFile(), keyPassword)
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
}
