package io.netty.util.internal.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;

/** @author galudisu */
public class NettyTlsUtils extends org.bouncycastle.tls.TlsUtils {

  /** No support TLSv1.3 for now */
  public static Certificate loadCertificateChain(TlsContext context, String[] resources)
      throws IOException {
    TlsCrypto crypto = context.getCrypto();
    var chain = new TlsCertificate[resources.length];
    for (var i = 0; i < resources.length; ++i) {
      chain[i] = loadCertificateResource(crypto, resources[i]);
    }
    return new Certificate(chain);
  }

  static TlsCertificate loadCertificateResource(TlsCrypto crypto, String resource)
      throws IOException {
    PemObject pem = loadPemResource(resource);
    if (pem.getType().endsWith("CERTIFICATE")) {
      return crypto.createCertificate(pem.getContent());
    }
    throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
  }

  public static AsymmetricKeyParameter loadBcPrivateKeyResource(String resource)
      throws IOException {
    PemObject pem = loadPemResource(resource);
    if (pem.getType().equals("PRIVATE KEY")) {
      return PrivateKeyFactory.createKey(pem.getContent());
    }
    if (pem.getType().equals("ENCRYPTED PRIVATE KEY")) {
      throw new UnsupportedOperationException("Encrypted PKCS#8 keys not supported");
    }
    if (pem.getType().equals("RSA PRIVATE KEY")) {
      var rsa = RSAPrivateKey.getInstance(pem.getContent());
      return new RSAPrivateCrtKeyParameters(
          rsa.getModulus(),
          rsa.getPublicExponent(),
          rsa.getPrivateExponent(),
          rsa.getPrime1(),
          rsa.getPrime2(),
          rsa.getExponent1(),
          rsa.getExponent2(),
          rsa.getCoefficient());
    }
    if (pem.getType().equals("EC PRIVATE KEY")) {
      var pKey = ECPrivateKey.getInstance(pem.getContent());
      var algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, pKey.getParameters());
      var privInfo = new PrivateKeyInfo(algId, pKey);
      return PrivateKeyFactory.createKey(privInfo);
    }
    throw new IllegalArgumentException("'resource' doesn't specify a valid private key");
  }

  public static PrivateKey loadJcaPrivateKeyResource(JcaTlsCrypto crypto, String resource)
      throws IOException {
    Throwable cause = null;
    try {
      PemObject pem = loadPemResource(resource);
      if (pem.getType().equals("PRIVATE KEY")) {
        return loadJcaPkcs8PrivateKey(crypto, pem.getContent());
      }
      if (pem.getType().equals("ENCRYPTED PRIVATE KEY")) {
        throw new UnsupportedOperationException("Encrypted PKCS#8 keys not supported");
      }
      if (pem.getType().equals("RSA PRIVATE KEY")) {
        var rsa = RSAPrivateKey.getInstance(pem.getContent());
        var keyFact = crypto.getHelper().createKeyFactory("RSA");
        return keyFact.generatePrivate(
            new RSAPrivateCrtKeySpec(
                rsa.getModulus(),
                rsa.getPublicExponent(),
                rsa.getPrivateExponent(),
                rsa.getPrime1(),
                rsa.getPrime2(),
                rsa.getExponent1(),
                rsa.getExponent2(),
                rsa.getCoefficient()));
      }
    } catch (GeneralSecurityException e) {
      cause = e;
    }
    throw new IllegalArgumentException("'resource' doesn't specify a valid private key", cause);
  }

  private static PrivateKey loadJcaPkcs8PrivateKey(JcaTlsCrypto crypto, byte[] encoded)
      throws GeneralSecurityException {
    var pki = PrivateKeyInfo.getInstance(encoded);
    AlgorithmIdentifier algID = pki.getPrivateKeyAlgorithm();
    ASN1ObjectIdentifier oid = algID.getAlgorithm();

    String name;
    if (X9ObjectIdentifiers.id_dsa.equals(oid)) {
      name = "DSA";
    } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(oid)) {
      // TODO Try ECDH/ECDSA according to intended use?
      name = "EC";
    } else if (PKCSObjectIdentifiers.rsaEncryption.equals(oid)
        || PKCSObjectIdentifiers.id_RSASSA_PSS.equals(oid)) {
      name = "RSA";
    } else if (EdECObjectIdentifiers.id_Ed25519.equals(oid)) {
      name = "Ed25519";
    } else if (EdECObjectIdentifiers.id_Ed448.equals(oid)) {
      name = "Ed448";
    } else {
      name = oid.getId();
    }

    var kf = crypto.getHelper().createKeyFactory(name);
    return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
  }

  private static PemObject loadPemResource(String resource) throws IOException {
    InputStream s = org.bouncycastle.tls.TlsUtils.class.getResourceAsStream("/" + resource);
    var p = new PemReader(new InputStreamReader(s));
    var o = p.readPemObject();
    p.close();
    return o;
  }
}
