package io.netty.util.internal.resources.openssl;

import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.ssl.*;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

/** SSLContext factory for handle client connection */
public final class SSLContextFactory {

  private SSLContextFactory() {}

  public static SslContext generateServerSslContext(
      Collection<Path> caPaths, Path keyPath, String keyStorePass)
      throws GeneralSecurityException, IOException {
    PrivateKey privateKey = PemUtils.readPrivateKey(keyPath, keyStorePass::toCharArray);
    List<X509Certificate> chain = PemUtils.readCertificates(caPaths);
    return SslContextBuilder.forServer(privateKey, keyStorePass, chain)
        .sslProvider(SslProvider.OPENSSL)
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
      Collection<Path> caPaths, Collection<Path> certPaths, Path keyPath, String keyStorePass)
      throws CertificateException, IOException {
    List<X509Certificate> certificate = PemUtils.readCertificates(certPaths);
    PrivateKey privateKey = PemUtils.readPrivateKey(keyPath, keyStorePass::toCharArray);
    List<X509Certificate> chain = PemUtils.readCertificates(caPaths);
    return SslContextBuilder.forClient()
        .sslProvider(SslProvider.OPENSSL)
        .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
        .trustManager(chain)
        .keyManager(privateKey, keyStorePass, certificate)
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
