package io.netty.util.internal.bc;

import io.netty.util.internal.utils.CertUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Objects;

@Slf4j
public class DtlsServer extends DefaultTlsServer {

  private AsymmetricKeyParameter privateKey;

  public DtlsServer() {
    super(new BcTlsCrypto(new SecureRandom()));
    try {
      privateKey =
          CertUtil.loadBcPrivateKeyResource(
              new File(
                  Objects.requireNonNull(
                          Thread.currentThread()
                              .getContextClassLoader()
                              .getResource("openssl/pkcs8_server.key"))
                      .getPath()),
              "server");
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Override
  protected ProtocolVersion[] getSupportedVersions() {
    return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10);
  }

  @Override
  public short getHeartbeatPolicy() {
    return HeartbeatMode.peer_allowed_to_send;
  }

  @Override
  public TlsHeartbeat getHeartbeat() {
    return new DefaultTlsHeartbeat(10_000, 10_000);
  }

  @Override
  protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException {
    var certs =
        CertUtil.loadBcCertificateChain(
            context.getCrypto(),
            new File(
                Objects.requireNonNull(
                        Thread.currentThread()
                            .getContextClassLoader()
                            .getResource("openssl/server.crt"))
                    .getPath()));
    if (certs == null) throw new TlsFatalAlert(AlertDescription.internal_error);

    return new BcDefaultTlsCredentialedDecryptor(
        (BcTlsCrypto) context.getCrypto(), certs, privateKey);
  }

  @Override
  protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
    var sigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs(); // NOSONAR
    if (sigAlgs == null) {
      // only support rsa !! for now.
      sigAlgs = TlsUtils.getDefaultSignatureAlgorithms(SignatureAlgorithm.rsa);
    }
    SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
    for (var i = 0; i < sigAlgs.size(); ++i) {
      SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm) sigAlgs.elementAt(i);
      if (alg.getSignature() == SignatureAlgorithm.rsa) {
        // Just grab the first one we find
        signatureAndHashAlgorithm = alg;
        break;
      }
    }

    if (signatureAndHashAlgorithm == null) {
      return null;
    }
    var certs =
        CertUtil.loadBcCertificateChain(
            context.getCrypto(),
            new File(
                Objects.requireNonNull(
                        Thread.currentThread()
                            .getContextClassLoader()
                            .getResource("openssl/server.crt"))
                    .getPath()),
            new File(
                Objects.requireNonNull(
                        Thread.currentThread()
                            .getContextClassLoader()
                            .getResource("openssl/ca.crt"))
                    .getPath()));
    if (certs == null) throw new TlsFatalAlert(AlertDescription.internal_error);
    return new BcDefaultTlsCredentialedSigner(
        new TlsCryptoParameters(context),
        (BcTlsCrypto) context.getCrypto(),
        privateKey,
        certs,
        signatureAndHashAlgorithm);
  }
}
