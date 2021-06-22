package io.netty.util.internal.bc;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.SecureRandom;

@Slf4j
public class DtlsServer extends DefaultTlsServer {

  private final SSLContext sslContext;
  private AsymmetricKeyParameter privateKey;

  public DtlsServer(SSLContext sslContext) {
    super(new BcTlsCrypto(new SecureRandom()));
    this.sslContext = sslContext;
    try {
      privateKey = NettyTlsUtils.loadBcPrivateKeyResource("openssl/server.key");
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Override
  protected int[] getSupportedCipherSuites() {
    return new int[] {
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
      CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
      CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
      CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
      CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
      CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
      CipherSuite.TLS_AES_256_GCM_SHA384,
      CipherSuite.TLS_AES_128_GCM_SHA256,
    };
  }

  @Override
  protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException {
    var certificate = NettyTlsUtils.loadCertificateChain(context, new String[] {"openssl/server.crt"});
    return new BcDefaultTlsCredentialedDecryptor(
        (BcTlsCrypto) context.getCrypto(), certificate, privateKey);
  }

  @Override
  protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
    var crypto = context.getCrypto();
    var cryptoParams = new TlsCryptoParameters(context);
    var certificate = NettyTlsUtils.loadCertificateChain(context, new String[] {"openssl/server.crt", "openssl/ca.crt"});

    return new BcDefaultTlsCredentialedSigner(
        cryptoParams,
        (BcTlsCrypto) crypto,
        privateKey,
        certificate,
        SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
  }

  @Override
  protected ProtocolVersion[] getSupportedVersions() {
    return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10);
  }
}
