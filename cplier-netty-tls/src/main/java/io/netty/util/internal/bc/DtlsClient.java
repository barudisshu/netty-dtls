package io.netty.util.internal.bc;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.util.Vector;

@Slf4j
public class DtlsClient extends DefaultTlsClient {

  private final TlsCrypto tlsCrypto;

  public DtlsClient(TlsCrypto tlsCrypto) {
    super(tlsCrypto);
    this.tlsCrypto = tlsCrypto;
  }

  @Override
  public TlsAuthentication getAuthentication() throws IOException {
    return new TlsAuthentication() {
      @Override
      public void notifyServerCertificate(TlsServerCertificate tlsServerCertificate) throws IOException {
        Certificate chain = tlsServerCertificate.getCertificate();
      }

      @Override
      public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
        short[] certificateTypes = certificateRequest.getCertificateTypes();
        if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign)) {
          return null;
        }

        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        Vector<?> sigAlgs = certificateRequest.getSupportedSignatureAlgorithms();
        if (sigAlgs != null) {
          for (int i = 0; i < sigAlgs.size(); ++i) {
            SignatureAndHashAlgorithm sigAlg = (SignatureAndHashAlgorithm) sigAlgs.elementAt(i);
            if (sigAlg.getSignature() == SignatureAlgorithm.rsa) {
              signatureAndHashAlgorithm = sigAlg;
              break;
            }
          }

          if (signatureAndHashAlgorithm == null) {
            return null;
          }
        }
        return new TlsCredentials() {
          @SneakyThrows
          @Override
          public Certificate getCertificate() {
            return (Certificate) tlsCrypto.createCertificate(certificateRequest.getCertificateRequestContext());
          }
        };
      }
    };
  }
}
