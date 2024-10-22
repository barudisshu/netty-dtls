package info.galudisu;

import io.netty.util.internal.utils.CertUtil;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;

import java.io.File;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Vector;

public class DtlsClient {

  public static void main(String[] args) throws Exception {
    var crypto = new BcTlsCrypto(new SecureRandom());
    var client =
        new DefaultTlsClient(crypto) {

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
          public TlsAuthentication getAuthentication() {
            return new TlsAuthentication() {
              @Override
              public void notifyServerCertificate(TlsServerCertificate serverCertificate) {}

              @Override
              public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                  throws IOException {
                short[] certificateTypes = certificateRequest.getCertificateTypes();
                if (certificateTypes == null
                    || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign)) {
                  return null;
                }

                SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
                Vector<?> sigAlgs = certificateRequest.getSupportedSignatureAlgorithms();
                if (sigAlgs != null) {
                  for (int i = 0; i < sigAlgs.size(); ++i) {
                    SignatureAndHashAlgorithm sigAlg =
                        (SignatureAndHashAlgorithm) sigAlgs.elementAt(i);
                    if (sigAlg.getSignature() == SignatureAlgorithm.rsa) {
                      signatureAndHashAlgorithm = sigAlg;
                      break;
                    }
                  }

                  if (signatureAndHashAlgorithm == null) {
                    return null;
                  }
                }
                var certs =
                    CertUtil.loadBcCertificateChain(
                        context.getCrypto(),
                        new File(
                            Objects.requireNonNull(
                                    Thread.currentThread()
                                        .getContextClassLoader()
                                        .getResource("openssl/client.crt"))
                                .getPath()),
                        new File(
                            Objects.requireNonNull(
                                    Thread.currentThread()
                                        .getContextClassLoader()
                                        .getResource("openssl/ca.crt"))
                                .getPath()));
                AsymmetricKeyParameter privateKey =
                    CertUtil.loadBcPrivateKeyResource(
                        new File(
                            Objects.requireNonNull(
                                    Thread.currentThread()
                                        .getContextClassLoader()
                                        .getResource("openssl/pkcs8_client.key"))
                                .getPath()),
                        "client");
                if (certs == null || privateKey == null) {
                  throw new TlsFatalAlert(AlertDescription.internal_error);
                }
                return new BcDefaultTlsCredentialedDecryptor(
                    (BcTlsCrypto) context.getCrypto(), certs, privateKey);
              }
            };
          }
        };

    int port = 4739;

    final DatagramSocket socket = new DatagramSocket(6573);
    socket.connect(InetAddress.getLocalHost(), port);

    final int mtu = 1500;
    DatagramTransport transport = new UDPTransport(socket, mtu);
    DTLSClientProtocol protocol = new DTLSClientProtocol();

    DTLSTransport dtls = protocol.connect(client, transport);

    System.out.println("Receive limit: " + dtls.getReceiveLimit());
    System.out.println("Send limit: " + dtls.getSendLimit());

    // Send and hopefully receive a packet back
    byte[] request = "Hello World".getBytes(StandardCharsets.UTF_8);
    dtls.send(request, 0, request.length);

    byte[] buf = new byte[dtls.getReceiveLimit()];
    while (!socket.isClosed()) {
      try {
        int len = dtls.receive(buf, 0, buf.length, 60000);
        if (len >= 0) {
          System.out.write(buf, 0, len);
        }
      } catch (SocketTimeoutException ste) {
      }
    }
    dtls.close();
  }
}
