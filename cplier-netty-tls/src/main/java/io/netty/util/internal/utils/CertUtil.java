package io.netty.util.internal.utils;

import com.google.common.collect.Lists;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * A BC certificate utility
 *
 * @see io.netty.util.internal.utils.BcGeneratorUtil
 * @author ehcayen
 */
@Slf4j
public final class CertUtil {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private CertUtil() {}

  /**
   * Loading jce private key object from a file and also provide the password is optional.
   *
   * <p>NOTE: Not support DHP convert!!!
   *
   * @param resource resource
   * @param pass password, optional
   * @return {@link PrivateKey}
   * @throws IOException ip exp
   */
  public static PrivateKey loadJcaPrivateKeyResource(File resource, String pass)
      throws IOException {
    AsymmetricKeyParameter asymmetricKeyParameter = loadBcPrivateKeyResource(resource, pass);
    if (asymmetricKeyParameter == null) {
      return null;
    }
    try {
      return io.netty.util.internal.utils.KeyUtil.generatePrivateKey(asymmetricKeyParameter);
    } catch (InvalidKeyException e) {
      throw new IllegalArgumentException("'resource' doesn't specify a valid private key");
    }
  }

  /**
   * Only support: DSA/DHP/ECDSA/RSA/RSAEncryption algorithm due to BC tls server implementation
   *
   * @param resource resource
   * @param pass password, optional
   * @return {@link AsymmetricKeyParameter}
   * @throws IOException io exp
   */
  public static AsymmetricKeyParameter loadBcPrivateKeyResource(
      File resource, String pass) throws IOException {
    List<PemObject> pemObjects = loadPemResource(resource);
    if (pemObjects.isEmpty()) {
      log.warn("BC provider parse empty private file");
      return null;
    }
    // to the private key, only one pem object
    var pem = pemObjects.get(0);
    log.trace("BC provider parse pem type: {}", pem.getType());
    // DSA
    if (pem.getType().equals("DSA PARAMETERS")) {
      var pKey = DSAParameter.getInstance(pem.getContent());
      var dsaParams = new DSAParameters(pKey.getP(), pKey.getG(), pKey.getQ());
      return new DSAPrivateKeyParameters(pKey.getG(), dsaParams);
    }
    // DHP
    if (pem.getType().equals("DH PARAMETERS")) {
      var pKey = DHParameter.getInstance(pem.getContent());
      var dhpParams = new DHParameters(pKey.getP(), pKey.getG(), pKey.getG());
      return new DHPrivateKeyParameters(pKey.getG(), dhpParams);
    }
    // private Key
    if (pem.getType().equals("PRIVATE KEY")) {
      return PrivateKeyFactory.createKey(pem.getContent());
    }
    // RSA
    if (pem.getType().equals("RSA PRIVATE KEY")) {
      // the RSA encryption
      if (StringUtils.isNotBlank(pass)) {
        try (var parser = new PEMParser(new FileReader(resource))) {
          PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) parser.readObject();
          PEMDecryptorProvider provider = new BcPEMDecryptorProvider(pass.toCharArray());
          PEMKeyPair keyPair = encryptedKeyPair.decryptKeyPair(provider);
          return PrivateKeyFactory.createKey(keyPair.getPrivateKeyInfo());
        }
      } else {
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
    }
    // ECDSA
    if (pem.getType().equals("EC PRIVATE KEY")) {
      var pKey = ECPrivateKey.getInstance(pem.getContent());
      var algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, pKey.getParameters());
      var privInfo = new PrivateKeyInfo(algId, pKey);
      return PrivateKeyFactory.createKey(privInfo);
    }
    // RSA PKCS8
    if (pem.getType().equals("ENCRYPTED PRIVATE KEY")) {
      try (var parser = new PEMParser(new FileReader(resource))) {
        PKCS8EncryptedPrivateKeyInfo pInfo = (PKCS8EncryptedPrivateKeyInfo) parser.readObject();
        try {
          if (StringUtils.isNotBlank(pass)) {
            var privateKeyInfo =
                pInfo.decryptPrivateKeyInfo(
                    new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(pass.toCharArray()));
            return PrivateKeyFactory.createKey(privateKeyInfo);
          }
        } catch (OperatorCreationException | PKCSException e) {
          log.warn("unable to parse pkcs8 private key: {}", e.getMessage());
        }
      }
    }
    throw new IllegalArgumentException("'resource' doesn't specify a valid private key");
  }

  /**
   * Resolve pem format files, loading into {@link X509Certificate} arrays
   *
   * @param resources {@link File}
   * @return {@link X509Certificate} array
   */
  public static X509Certificate[] loadJacCertificateChain(File... resources) throws IOException {
    List<X509Certificate> x509Certificates = new ArrayList<>();
    for (File resource : resources) {
      var certs = loadJacCertificateChain(resource);
      x509Certificates.addAll(certs);
    }
    return x509Certificates.toArray(new X509Certificate[0]);
  }

  private static List<X509Certificate> loadJacCertificateChain(File resource) throws IOException {
    List<PemObject> pemObjects = loadPemResource(resource);
    if (pemObjects.isEmpty()) {
      log.warn("BC provider parse empty certificate file");
      return Lists.newArrayList();
    }
    List<X509Certificate> x509Certificates = new ArrayList<>();
    for (PemObject pemObject : pemObjects) {
      X509Certificate x509Certificate = loadJacCertificateResource(pemObject);
      x509Certificates.add(x509Certificate);
    }
    return x509Certificates;
  }

  private static X509Certificate loadJacCertificateResource(PemObject pemObject)
      throws IOException {
    if (pemObject.getType().endsWith("CERTIFICATE")) {
      var converter =
          new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
      var x509CertificateHolder = new X509CertificateHolder(pemObject.getContent());
      try {
        return converter.getCertificate(x509CertificateHolder);
      } catch (CertificateException ignored) { // NOSONAR
        // This exception wont panic actually
      }
    }
    throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
  }

  /**
   * Resolve pem format files, also check that file exists but with no-content
   *
   * @param crypto {@link org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto}
   * @param resources {@link File}
   * @return {@link Certificate}
   * @throws IOException ex
   */
  public static Certificate loadBcCertificateChain(TlsCrypto crypto, File... resources)
      throws IOException {
    List<TlsCertificate> chain = Lists.newLinkedList();
    for (File resource : resources) {
      var certs = loadCertificateResource(crypto, resource);
      chain.addAll(certs);
    }
    if (chain.isEmpty()) return null;
    return new Certificate(chain.toArray(new TlsCertificate[0]));
  }

  private static List<TlsCertificate> loadCertificateResource(TlsCrypto crypto, File resource)
      throws IOException {
    List<PemObject> pemObjects = loadPemResource(resource);
    if (pemObjects.isEmpty()) {
      log.warn("BC provider parse empty certificate file");
      return Lists.newArrayList();
    }
    List<TlsCertificate> tlsCertificates = new ArrayList<>(pemObjects.size());
    for (PemObject pemObject : pemObjects) {
      if (pemObject.getType().endsWith("CERTIFICATE")) {
        TlsCertificate certificate = crypto.createCertificate(pemObject.getContent());
        tlsCertificates.add(certificate);
      } else throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
    }
    return tlsCertificates;
  }

  /**
   * Pem format file reader
   *
   * @param resource file resource
   * @return object
   * @throws IOException io exp
   */
  private static List<PemObject> loadPemResource(File resource) throws IOException {
    List<PemObject> pemObjects = Lists.newLinkedList();
    try (var p = new PemReader(new InputStreamReader(new FileInputStream(resource)))) {
      while (true) {
        var pemObject = p.readPemObject();
        if (pemObject != null) {
          pemObjects.add(pemObject);
        } else {
          break;
        }
      }
    }
    return pemObjects;
  }
}
