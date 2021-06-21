package io.netty.util.internal.bc;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Vector;

@Slf4j
public class DtlsServer extends DefaultTlsServer {

  private final SSLContext sslContext;

  public DtlsServer(SSLContext sslContext) {
    super(new BcTlsCrypto(new SecureRandom()));
    this.sslContext = sslContext;
  }

  @Override
  public void notifyAlertRaised(
      short alertLevel, short alertDescription, String message, Throwable cause) {
    var details =
        String.format(
            "DTLS server raised alert: %s, %s",
            AlertLevel.getText(alertLevel), AlertDescription.getText(alertDescription));
    if (message != null) {
      details += "> " + message;
    }
    if (cause != null) {
      log.error(details, cause);
    }
    if (alertLevel == AlertLevel.fatal) {
      log.error(details);
    } else {
      log.debug(details);
    }
  }

  @Override
  public void notifyAlertReceived(short alertLevel, short alertDescription) {
    var details =
        String.format(
            "DTLS server received alert: %s, %s",
            AlertLevel.getText(alertLevel), AlertDescription.getText(alertDescription));
    if (alertLevel == AlertLevel.fatal) {
      log.error(details);
    } else {
      log.debug(details);
    }
  }

  @Override
  public ProtocolVersion getServerVersion() throws IOException {
    ProtocolVersion serverVersion = super.getServerVersion();
    log.debug("DTLS server negotiated {}", serverVersion);
    return serverVersion;
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
    certificateAuthorities.addElement(CertificateRequest.parse(context, Thread.currentThread().getContextClassLoader().getResourceAsStream("openssl/ca.crt")));
    certificateAuthorities.addElement(
        CertificateRequest.parse(context, Thread.currentThread().getContextClassLoader().getResourceAsStream("openssl/client.crt")));
    certificateAuthorities.addElement(
        CertificateRequest.parse(context, Thread.currentThread().getContextClassLoader().getResourceAsStream("openssl/client.key")));

    return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
  }

  @Override
  public void notifyClientCertificate(Certificate clientCertificate) throws IOException {
    TlsCertificate[] chain = clientCertificate.getCertificateList();

    TlsCertificate[] certPath = null;

    if (null == certPath) {
      throw new TlsFatalAlert(AlertDescription.bad_certificate);
    }

    TlsUtils.checkPeerSigAlgs(context, certPath);
  }

  @Override
  public void notifyHandshakeComplete() throws IOException {
    super.notifyHandshakeComplete();

    byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
    log.debug("Server 'tls-server-end-point': {}", hex(tlsServerEndPoint));

    byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
    log.debug("Server 'tls-unique': {}", hex(tlsUnique));
  }

//  protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException {
//    log.debug("==> ");
//    return TlsUtils.loadEncryptionCredentials(
//        context,
//        new String[] {"x509-server-rsa-enc.pem", "x509-ca-rsa.pem"},
//        "x509-server-key-rsa-enc.pem");
//  }

  @Override
  protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
    Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();

    return TlsUtils.loadSignerCredentialsServer(context, clientSigAlgs, SignatureAlgorithm.rsa);
  }

  protected String hex(byte[] data) {
    return data == null ? "(null)" : Hex.toHexString(data);
  }

  @Override
  protected ProtocolVersion[] getSupportedVersions() {
    return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10);
  }
}
