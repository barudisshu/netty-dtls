package io.netty.util.internal.utils;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObjectGenerator;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * A certificate generator util. use for CT or FT test case as you wish. NOTE: only test for RSA
 * algorithm.
 *
 * @see CertUtil
 * @author ehcayen
 */
public final class BcGeneratorUtil {

  static {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  private BcGeneratorUtil() {}

  @SuppressWarnings("java:S5738")
  public static Certificate x509CertToBcCert(
      BcTlsCrypto crypto, final X509Certificate x509Certificate)
      throws CertificateEncodingException, IOException {
    return x509CertsToBcCert(crypto, new X509Certificate[] {x509Certificate});
  }

  @SuppressWarnings("java:S5738")
  public static Certificate x509CertsToBcCert(
      BcTlsCrypto crypto, final X509Certificate[] x509Certificates)
      throws CertificateEncodingException, IOException {
    List<BcTlsCertificate> bcTlsCertificates = new ArrayList<>(x509Certificates.length);
    for (X509Certificate x509Certificate : x509Certificates) {
      BcTlsCertificate bcTlsCertificate =
          new BcTlsCertificate(crypto, x509Certificate.getEncoded());
      bcTlsCertificates.add(bcTlsCertificate);
    }
    return new Certificate(bcTlsCertificates.toArray(new TlsCertificate[0]));
  }

  @SuppressWarnings("java:S5738")
  public static X509Certificate bcCertToX509Cert(final Certificate certificate)
      throws CertificateException, IOException {
    return bcCertToX509Certs(certificate)[0];
  }

  @SuppressWarnings("java:S5738")
  public static X509Certificate[] bcCertToX509Certs(final Certificate certificate)
      throws CertificateException, IOException {
    List<X509Certificate> x509Certificates =
        new ArrayList<>(certificate.getCertificateList().length);
    JcaX509CertificateConverter converter =
        new JcaX509CertificateConverter().setProvider(CertGeneratorParameter.PROVIDER_NAME);
    for (TlsCertificate tlsCertificate : certificate.getCertificateList()) {
      org.bouncycastle.asn1.x509.Certificate x509Certificate =
          org.bouncycastle.asn1.x509.Certificate.getInstance(tlsCertificate.getEncoded());
      X509CertificateHolder certHolder = new X509CertificateHolder(x509Certificate);
      x509Certificates.add(converter.getCertificate(certHolder));
    }
    return x509Certificates.toArray(new X509Certificate[0]);
  }

  public static JcaKeyPair exportX509CaChain(
      KeyPair rootKeyPair, X500Name rootCertIssuer, TimeSlot timeSlot, String password, Path path)
      throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException,
          KeyStoreException, NoSuchProviderException {
    JcaKeyPair jcaKeyPair = generateX509CaChain(rootKeyPair, timeSlot, rootCertIssuer);
    var rootCert = jcaKeyPair.getX509Certificate();
    writeX509ToFileBase64Encoded(rootCert, path.resolve("root-cert.cer").toString());
    exportKeyPairToKeystoreFile(
        rootKeyPair,
        rootCert,
        path.resolve("root-cert").toString(),
        path.resolve("root-cert.pfx").toString(),
        password);
    return jcaKeyPair;
  }

  public static JcaKeyPair exportCertificate( // NOSONAR
      KeyPair rootKeyPair,
      KeyPair issuedCertKeyPair,
      X509Certificate rootCert,
      X500Name rootCertIssuer,
      X500Name issuedCertSubject,
      TimeSlot timeSlot,
      String dNSName,
      String iPAddress,
      String password,
      Path path)
      throws CertificateException, IOException, NoSuchAlgorithmException, SignatureException,
          OperatorCreationException, InvalidKeyException, NoSuchProviderException,
          KeyStoreException {
    JcaKeyPair jcaKeyPair =
        generateX509CertificateAndKey(
            rootKeyPair,
            issuedCertKeyPair,
            rootCert,
            rootCertIssuer,
            issuedCertSubject,
            timeSlot,
            dNSName,
            iPAddress);
    var issuedCert = jcaKeyPair.getX509Certificate();
    writeX509ToFileBase64Encoded(issuedCert, path.resolve("issued-cert.cer").toString());
    exportKeyPairToKeystoreFile(
        issuedCertKeyPair,
        issuedCert,
        path.resolve("issued-cert").toString(),
        path.resolve("issued-cert.pfx").toString(),
        password);
    return jcaKeyPair;
  }

  @SuppressWarnings("java:S5738")
  public static BcKeyPair generateBcCaChain(
      BcTlsCrypto crypto, KeyPair rootKeyPair, TimeSlot timeSlot, X500Name rootCertIssuer)
      throws CertificateException, NoSuchAlgorithmException, OperatorCreationException,
          IOException {
    JcaKeyPair jcaKeyPair = generateX509CaChain(rootKeyPair, timeSlot, rootCertIssuer);
    AsymmetricKeyParameter privateKey =
        buildAsymmetricKeyParameter(jcaKeyPair.getKeyPair().getPrivate());
    Certificate certificate = x509CertToBcCert(crypto, jcaKeyPair.getX509Certificate());
    return new BcKeyPair(privateKey, certificate);
  }

  @SuppressWarnings("java:S5738")
  public static BcKeyPair generateBcCertificateAndKey( // NOSONAR
      BcTlsCrypto crypto,
      KeyPair rootKeyPair,
      KeyPair issuedCertKeyPair,
      final Certificate rootCert,
      X500Name rootCertIssuer,
      X500Name issuedCertSubject,
      TimeSlot timeSlot,
      String dNSName,
      String iPAddress)
      throws CertificateException, NoSuchAlgorithmException, SignatureException,
          OperatorCreationException, InvalidKeyException, NoSuchProviderException, IOException {
    JcaKeyPair jcaKeyPair =
        generateX509CertificateAndKey(
            rootKeyPair,
            issuedCertKeyPair,
            bcCertToX509Cert(rootCert),
            rootCertIssuer,
            issuedCertSubject,
            timeSlot,
            dNSName,
            iPAddress);
    var keyPair = jcaKeyPair.getKeyPair();
    var x509Certificate = jcaKeyPair.getX509Certificate();
    var privateKey = buildAsymmetricKeyParameter(keyPair.getPrivate());
    return new BcKeyPair(privateKey, x509CertToBcCert(crypto, x509Certificate));
  }

  private static AsymmetricKeyParameter buildAsymmetricKeyParameter(PrivateKey privateKey)
      throws IOException {
    return PrivateKeyFactory.createKey(privateKey.getEncoded());
  }

  /**
   * Generate a ca chain
   *
   * @param timeSlot if negative, generate an expire certificate
   * @param rootCertIssuer issuer, such as: `CN=root-cert`
   * @return {@link JcaKeyPair}
   */
  public static JcaKeyPair generateX509CaChain(
      KeyPair rootKeyPair, TimeSlot timeSlot, X500Name rootCertIssuer)
      throws NoSuchAlgorithmException, OperatorCreationException, IOException,
          CertificateException {

    // First step is to create a root certificate
    // First Generate a KeyPair,
    // then a random serial number
    // then generate a certificate using the KeyPair
    BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

    // Issued By and Issued To same for root certificate
    ContentSigner rootCertContentSigner =
        new JcaContentSignerBuilder(CertGeneratorParameter.SHA_1_WITH_RSA)
            .setProvider(CertGeneratorParameter.PROVIDER_NAME)
            .build(rootKeyPair.getPrivate());
    X509v3CertificateBuilder rootCertBuilder =
        new JcaX509v3CertificateBuilder(
            rootCertIssuer,
            rootSerialNum,
            timeSlot.getStartDate(),
            timeSlot.getEndDate(),
            rootCertIssuer,
            rootKeyPair.getPublic());

    // Add Extensions
    // A BasicConstraint to mark root certificate as CA certificate
    JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
    // some cert path analysers will reject a v3 certificate as a CA if it doesn't have basic
    // contains set.
    rootCertBuilder.addExtension(
        Extension.basicConstraints, true, new BasicConstraints(true).getEncoded());

    rootCertBuilder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

    // Create a cert holder and export to X509Certificate
    X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
    X509Certificate rootCert =
        new JcaX509CertificateConverter()
            .setProvider(CertGeneratorParameter.PROVIDER_NAME)
            .getCertificate(rootCertHolder);
    return new JcaKeyPair(rootKeyPair, rootCert);
  }

  public static JcaKeyPair generateX509CertificateAndKey( // NOSONAR
      KeyPair rootKeyPair,
      KeyPair issuedCertKeyPair,
      final X509Certificate rootCert,
      X500Name rootCertIssuer,
      X500Name issuedCertSubject,
      TimeSlot timeSlot,
      String dNSName,
      String iPAddress)
      throws OperatorCreationException, NoSuchAlgorithmException, IOException, CertificateException,
          SignatureException, InvalidKeyException, NoSuchProviderException {
    // Generate a new KeyPair and sign it using the Root Cert Private Key
    // by generating a CSR (Certificate Signing Request)
    BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

    PKCS10CertificationRequestBuilder p10Builder =
        new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
    JcaContentSignerBuilder csrBuilder =
        new JcaContentSignerBuilder(CertGeneratorParameter.SHA_1_WITH_RSA)
            .setProvider(CertGeneratorParameter.PROVIDER_NAME);

    // Sign the new KeyPair with the root cert Private Key
    ContentSigner csrContentSigner = csrBuilder.build(rootKeyPair.getPrivate());
    PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

    // Use the Signed KeyPair and CSR to generate an issued Certificate
    // Here serial number is randomly generated. In general, CAs use
    // a sequence to generate Serial number and avoid collisions
    X509v3CertificateBuilder issuedCertBuilder =
        new X509v3CertificateBuilder(
            rootCertIssuer,
            issuedCertSerialNum,
            timeSlot.getStartDate(),
            timeSlot.getEndDate(),
            csr.getSubject(),
            csr.getSubjectPublicKeyInfo());

    JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

    // Add Extensions
    // Use BasicConstraints to say that this Cert is not a CA
    issuedCertBuilder.addExtension(
        Extension.basicConstraints, true, new BasicConstraints(false).getEncoded());

    // Add Issuer cert identifier as Extension
    issuedCertBuilder.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
    issuedCertBuilder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

    // Add intended key usage extension if needed
    // NOTE: Only usage for digital signature since X509v3 protocol default
    issuedCertBuilder.addExtension(
        Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

    // Add DNS name is cert is to used for SSL
    issuedCertBuilder.addExtension(
        Extension.subjectAlternativeName,
        false,
        new DERSequence(
            new ASN1Encodable[] {
              new GeneralName(GeneralName.dNSName, dNSName),
              new GeneralName(GeneralName.iPAddress, iPAddress)
            }));

    X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
    X509Certificate issuedCert =
        new JcaX509CertificateConverter()
            .setProvider(CertGeneratorParameter.PROVIDER_NAME)
            .getCertificate(issuedCertHolder);

    // Verify the issued cert signature against the root (issuer) cert
    issuedCert.verify(rootCert.getPublicKey(), CertGeneratorParameter.PROVIDER_NAME);
    return new JcaKeyPair(issuedCertKeyPair, issuedCert);
  }

  private static void exportKeyPairToKeystoreFile( // NOSONAR
      KeyPair keyPair,
      final X509Certificate certificate,
      String alias,
      String fileName,
      String storePass)
      throws KeyStoreException, NoSuchProviderException, CertificateException, IOException,
          NoSuchAlgorithmException {
    KeyStore sslKeyStore = KeyStore.getInstance("PKCS12", CertGeneratorParameter.PROVIDER_NAME);
    sslKeyStore.load(null, null);
    sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(), null, new X509Certificate[] {certificate});
    try (FileOutputStream keyStoreOs = new FileOutputStream(fileName)) {
      sslKeyStore.store(keyStoreOs, storePass.toCharArray());
    }
  }

  public static void writeCertToFileBase64Encoded(final Certificate certificate, String fileName)
      throws IOException, CertificateException {
    try (FileOutputStream certificateOut = new FileOutputStream(fileName)) {
      X509Certificate[] x509Certificates = bcCertToX509Certs(certificate);
      for (X509Certificate x509Certificate : x509Certificates) {
        certificateOut.write("-----BEGIN CERTIFICATE-----\n".getBytes());
        certificateOut.write(Base64.encode(x509Certificate.getEncoded()));
        certificateOut.write("\n-----END CERTIFICATE-----".getBytes());
      }
    }
  }

  public static void writeX509ToFileBase64Encoded(
      final X509Certificate certificate, String fileName)
      throws IOException, CertificateEncodingException {
    try (FileOutputStream certificateOut = new FileOutputStream(fileName)) {
      certificateOut.write("-----BEGIN CERTIFICATE-----\n".getBytes());
      certificateOut.write(Base64.encode(certificate.getEncoded()));
      certificateOut.write("\n-----END CERTIFICATE-----".getBytes());
    }
  }

  public static void writePasswordToFile(final String storePass, String fileName)
      throws IOException {
    try (FileOutputStream passOut = new FileOutputStream(fileName)) {
      passOut.write(storePass.getBytes(StandardCharsets.UTF_8));
    }
  }

  public static void writeAsymmetricKeyParameterToFile(
      final AsymmetricKeyParameter privateKey, String fileName, String storePass)
      throws IOException, OperatorCreationException {
    try (FileOutputStream privateKeyOut = new FileOutputStream(fileName)) {
      try (JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(privateKeyOut))) {
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey);
        OutputEncryptor outputEncryptor =
            new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setPassword(storePass.toCharArray())
                .build();
        PemObjectGenerator pemObjectGenerator = new PKCS8Generator(privateKeyInfo, outputEncryptor);
        writer.writeObject(pemObjectGenerator);
      }
    }
  }

  /**
   * Create the certificate time slot, if year is negative, transform to expired one.
   *
   * @param year pre-long years
   * @return {@link TimeSlot}
   */
  public static TimeSlot generateTimeSlot(int year) {
    Calendar calendar = Calendar.getInstance();
    Date startDate;
    Date endDate;
    if (year >= 0) {
      calendar.add(Calendar.DATE, -1);
      startDate = calendar.getTime();
      calendar.add(Calendar.YEAR, year);
    } else {
      // expired date
      calendar.add(Calendar.YEAR, year);
      startDate = calendar.getTime();
      calendar.add(Calendar.DATE, +1);
      // end date was yesterday
    }
    endDate = calendar.getTime();
    return new TimeSlot(startDate, endDate);
  }

  public static KeyPairGenerator generateKeyPairGenerator()
      throws NoSuchAlgorithmException, NoSuchProviderException {
    return generateKeyPairGenerator(
        CertGeneratorParameter.ALGORITHM, CertGeneratorParameter.KEY_SIZE);
  }

  public static KeyPairGenerator generateKeyPairGenerator(String algorithm, int keySize)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator keyPairGenerator =
        KeyPairGenerator.getInstance(algorithm, CertGeneratorParameter.PROVIDER_NAME);
    keyPairGenerator.initialize(keySize);
    return keyPairGenerator;
  }

  /** Need to store the bc object */
  @Getter
  @AllArgsConstructor
  @SuppressWarnings("java:S5738")
  public static class BcKeyPair {
    final AsymmetricKeyParameter privateKey;
    final Certificate certificate;
  }

  /**
   * Need to store the target
   *
   * @author ehcayen
   */
  @Getter
  @AllArgsConstructor
  public static class JcaKeyPair {
    final KeyPair keyPair;
    final X509Certificate x509Certificate;
  }

  @Getter
  @AllArgsConstructor
  public static class TimeSlot {
    final Date startDate;
    final Date endDate;
  }

  /** A Dynamic parameter for generator. */
  private static class CertGeneratorParameter {
    private static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    private static final String ALGORITHM = "RSA";
    private static final String SHA_1_WITH_RSA = "SHA1withRSA";
    private static final int KEY_SIZE = 2048;
  }
}
