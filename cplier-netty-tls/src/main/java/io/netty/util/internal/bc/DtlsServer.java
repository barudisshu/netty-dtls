package io.netty.util.internal.bc;

import io.netty.util.internal.cert.jsse.SslStream;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

@Slf4j
public class DtlsServer extends DefaultTlsServer {

  private AsymmetricKeyParameter privateKey;

  public DtlsServer() {
    super(new BcTlsCrypto(new SecureRandom()));
    try {
      privateKey =
          NettyTlsUtils.loadBcPrivateKeyResource(
              Thread.currentThread()
                  .getContextClassLoader()
                  .getResourceAsStream("openssl/server.key"));
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
        NettyTlsUtils.loadCertificateChain(
            context,
            new InputStream[] {
              Thread.currentThread()
                  .getContextClassLoader()
                  .getResourceAsStream("openssl/server.crt")
            });

    return new BcDefaultTlsCredentialedDecryptor(
        (BcTlsCrypto) context.getCrypto(), certs, privateKey);
  }

  @Override
  protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
    var sigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();
    if (sigAlgs == null) {
      // only support rsa !! for now.
      sigAlgs = NettyTlsUtils.getDefaultSignatureAlgorithms(SignatureAlgorithm.rsa);
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
        NettyTlsUtils.loadCertificateChain(
            context,
            new InputStream[] {
              Thread.currentThread()
                  .getContextClassLoader()
                  .getResourceAsStream("openssl/server.crt"),
              Thread.currentThread().getContextClassLoader().getResourceAsStream("openssl/ca.crt")
            });
    return new BcDefaultTlsCredentialedSigner(
        new TlsCryptoParameters(context),
        (BcTlsCrypto) context.getCrypto(),
        privateKey,
        certs,
        signatureAndHashAlgorithm);
  }
}
