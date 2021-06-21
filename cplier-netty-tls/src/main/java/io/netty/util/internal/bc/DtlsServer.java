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
import java.util.Vector;

@Slf4j
public class DtlsServer extends DefaultTlsServer {

  private final SSLContext sslContext;
  private AsymmetricKeyParameter privateKey;

  public DtlsServer(SSLContext sslContext) {
    super(new BcTlsCrypto(new SecureRandom()));
    this.sslContext = sslContext;
    try {
      privateKey = TlsUtils.loadBcPrivateKeyResource("openssl/server.key");
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Override
  public CertificateRequest getCertificateRequest() throws IOException {
    log.debug("==>");
    short[] certificateTypes =
        new short[] {
          ClientCertificateType.rsa_sign,
          ClientCertificateType.dss_sign,
          ClientCertificateType.ecdsa_sign
        };

    Vector serverSigAlgs = null;
    if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion())) {
      serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
    }

    Vector certificateAuthorities = new Vector();
    return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
  }

  @Override
  protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException {
    Certificate certs =
        TlsUtils.loadCertificateChain(
            context, new String[] {"openssl/ca.crt", "openssl/server.crt"});
    return new BcDefaultTlsCredentialedDecryptor(
        (BcTlsCrypto) context.getCrypto(), certs, privateKey);
  }

  @Override
  protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
    Certificate certs =
        TlsUtils.loadCertificateChain(
            context, new String[] {"openssl/ca.crt", "openssl/server.crt"});
    return new BcDefaultTlsCredentialedSigner(
        new TlsCryptoParameters(context),
        (BcTlsCrypto) context.getCrypto(),
        privateKey,
        certs,
        SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
  }

  @Override
  protected ProtocolVersion[] getSupportedVersions() {
    return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10);
  }
}
