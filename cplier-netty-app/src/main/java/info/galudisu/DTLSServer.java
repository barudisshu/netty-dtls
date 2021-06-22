package info.galudisu;

import io.netty.util.internal.bc.NettyTlsUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.SecureRandom;
import java.util.Vector;

public class DTLSServer {
  public static void main(String[] args) throws Exception {
    var crypto = new BcTlsCrypto(new SecureRandom());
    var server =
        new DefaultTlsServer(crypto) {

          @Override
          protected ProtocolVersion[] getSupportedVersions() {
            return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10);
          }

          @Override
          protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException {
            var certs =
                NettyTlsUtils.loadCertificateChain(context, new String[] {"openssl/server.crt"});
            AsymmetricKeyParameter privateKey =
                NettyTlsUtils.loadBcPrivateKeyResource("openssl/server.key");

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
                    context, new String[] {"openssl/server.crt", "openssl/ca.crt"});
            AsymmetricKeyParameter privateKey =
                NettyTlsUtils.loadBcPrivateKeyResource("openssl/server.key");
            return new BcDefaultTlsCredentialedSigner(
                new TlsCryptoParameters(context),
                (BcTlsCrypto) context.getCrypto(),
                privateKey,
                certs,
                signatureAndHashAlgorithm);
          }
        };

    var port = 54321;
    var mtu = 1500;

    var data = new byte[mtu];
    var packet = new DatagramPacket(data, mtu);
    var socket = new DatagramSocket(port);

    socket.receive(packet);
    System.out.println(
        "Accepting connection from "
            + packet.getAddress().getHostAddress()
            + ":"
            + packet.getPort());
    socket.connect(packet.getAddress(), packet.getPort());

    DatagramTransport transport = new UDPTransport(socket, mtu);
    var protocol = new DTLSServerProtocol();

    DTLSTransport dtls = protocol.accept(server, transport);

    var buf = new byte[dtls.getReceiveLimit()];

    while (!socket.isClosed()) {
      int len = dtls.receive(buf, 0, buf.length, 60000);
      if (len >= 0) {
        System.out.write(buf, 0, len);
        dtls.send(buf, 0, len);
      }
    }

    dtls.close();
  }
}
