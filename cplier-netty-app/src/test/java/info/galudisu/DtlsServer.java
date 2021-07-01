package info.galudisu;

import io.netty.util.internal.bc.NettyTlsUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.Vector;

public class DtlsServer {
  public static void main(String[] args) throws Exception {
    var crypto = new BcTlsCrypto(new SecureRandom());
    var server =
        new DefaultTlsServer(crypto) {

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
            Certificate certs =
                NettyTlsUtils.loadCertificateChain(
                    context,
                    new InputStream[] {
                      Thread.currentThread()
                          .getContextClassLoader()
                          .getResourceAsStream("openssl/server.crt")
                    });
            AsymmetricKeyParameter privateKey =
                NettyTlsUtils.loadBcPrivateKeyResource(
                    Thread.currentThread()
                        .getContextClassLoader()
                        .getResourceAsStream("openssl/server.key"));

            return new BcDefaultTlsCredentialedDecryptor(
                (BcTlsCrypto) context.getCrypto(), certs, privateKey);
          }

          @Override
          protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
            Vector sigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();

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
                      Thread.currentThread()
                          .getContextClassLoader()
                          .getResourceAsStream("openssl/ca.crt")
                    });
            AsymmetricKeyParameter privateKey =
                NettyTlsUtils.loadBcPrivateKeyResource(
                    Thread.currentThread()
                        .getContextClassLoader()
                        .getResourceAsStream("openssl/server.key"));
            return new BcDefaultTlsCredentialedSigner(
                new TlsCryptoParameters(context),
                (BcTlsCrypto) context.getCrypto(),
                privateKey,
                certs,
                signatureAndHashAlgorithm);
          }
        };

    int port = 4739;
    final int mtu = 1500;

    byte[] data = new byte[mtu];
    final DatagramPacket packet = new DatagramPacket(data, mtu);
    final DatagramSocket socket = new DatagramSocket(port);

    socket.receive(packet);
    System.out.println(
        "Accepting connection from "
            + packet.getAddress().getHostAddress()
            + ":"
            + packet.getPort());
    socket.connect(packet.getAddress(), packet.getPort());

    DatagramTransport transport = new UDPTransport(socket, mtu);
    DTLSServerProtocol protocol = new DTLSServerProtocol();

    DTLSTransport dtls = protocol.accept(server, transport);

    byte[] buf = new byte[dtls.getReceiveLimit()];

    while (!socket.isClosed()) {
      try {
        int len = dtls.receive(buf, 0, buf.length, 60000);
        if (len >= 0) {
          System.out.write(buf, 0, len);
          dtls.send(buf, 0, len);
        }
      } catch (SocketTimeoutException ste) {
          ste.printStackTrace();
      }
    }

    dtls.close();
  }
}
