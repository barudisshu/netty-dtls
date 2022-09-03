package io.netty.util.internal.cert.bctls.domain;

import io.netty.util.internal.cert.bctls.domain.KeyStoreManager.SignerInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static io.netty.util.internal.cert.bctls.domain.CertificateGenerator.SignatureAlgorithm.SHA384WITHECDSA;

public class CertificateGenerator {

  public enum SignatureAlgorithm {
    SHA384WITHECDSA("SHA384WITHECDSA"),
    SHA384WITHRSA("SHA384WITHRSA");

    private final String id;

    private SignatureAlgorithm(String id) {
      this.id = id;
    }

    public String getAlgorithmName() {
      return id;
    }
  }

  private final BouncyCastleProvider provider;
  private final SecureRandom secureRandom;

  public CertificateGenerator(BouncyCastleProvider provider, SecureRandom secureRandom) {
    this.provider = provider;
    this.secureRandom = secureRandom;
  }

  public Certificate generateRootCertificate(KeyPair keyPair, String subject, Duration validity) {
    return generateRootCertificate(keyPair, subject, validity, guessSigAlg(keyPair.getPrivate()));
  }

  private SignatureAlgorithm guessSigAlg(PrivateKey privateKey) {
    SignatureAlgorithm sigAlg;
    if (privateKey instanceof ECPrivateKey) {
      sigAlg = SHA384WITHECDSA;
    } else if (privateKey instanceof RSAPrivateKey) {
      sigAlg = SignatureAlgorithm.SHA384WITHRSA;
    } else {
      throw new IllegalArgumentException(
          "Unable to identify a suitable signature algorithm for the supplied key");
    }
    return sigAlg;
  }

  public Certificate generateRootCertificate(
      KeyPair keyPair, String subject, Duration validity, SignatureAlgorithm sigAlg) {

    var x500subject = X500Name.getInstance(new X500Principal("CN=" + subject).getEncoded());
    BigInteger serial = newSerial();

    return signCertificate(
        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()),
        x500subject,
        serial,
        x500subject,
        serial,
        validity,
        keyPair.getPrivate(),
        sigAlg,
        true);
  }

  private BigInteger newSerial() {
    return new BigInteger(128, secureRandom);
  }

  public String generateCertificateSigningRequest(KeyPair keyPair, String subject) {
    return generateCertificateSigningRequest(keyPair, subject, guessSigAlg(keyPair.getPrivate()));
  }

  public String generateCertificateSigningRequest(
      KeyPair keyPair, String subject, SignatureAlgorithm sigAlg) {
    PKCS10CertificationRequestBuilder p10Builder =
        new JcaPKCS10CertificationRequestBuilder(
            new X500Principal("CN=" + subject), keyPair.getPublic());

    var csBuilder = new JcaContentSignerBuilder(sigAlg.getAlgorithmName());
    csBuilder.setProvider(provider);

    try (var writer = new StringWriter();
        var pemWriter = new JcaPEMWriter(writer)) {

      ContentSigner signer = csBuilder.build(keyPair.getPrivate());
      PKCS10CertificationRequest csr = p10Builder.build(signer);

      pemWriter.writeObject(csr);
      pemWriter.flush();
      return writer.toString();
    } catch (IOException | OperatorCreationException e) {
      throw new RuntimeException(e);
    }
  }

  public String signCertificate(SignerInfo signerInfo, String signingRequest) {
    try {
      PKCS10CertificationRequest req;
      try (var parser = new PEMParser(new StringReader(signingRequest))) {
        req = (PKCS10CertificationRequest) parser.readObject();
      }

      var reqPublicKey = req.getSubjectPublicKeyInfo();
      if (!req.isSignatureValid(
          new JcaContentVerifierProviderBuilder().setProvider(provider).build(reqPublicKey))) {
        throw new IllegalArgumentException(
            "The signing request failed validation. Has it been tampered with?");
      }

      X509Certificate caCert = (X509Certificate) signerInfo.trustChain[0];
      var issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
      BigInteger issuerSerial = caCert.getSerialNumber();

      var cert =
          signCertificate(
              reqPublicKey,
              req.getSubject(),
              newSerial(),
              issuer,
              issuerSerial,
              Duration.ofDays(365),
              signerInfo.privateKey,
              guessSigAlg(signerInfo.privateKey),
              false);

      try (var writer = new StringWriter();
          var pemWriter = new JcaPEMWriter(writer)) {

        pemWriter.writeObject(cert);

        for (Certificate c : signerInfo.trustChain) {
          pemWriter.writeObject(c);
        }
        pemWriter.flush();
        return writer.toString();
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private Certificate signCertificate(
      SubjectPublicKeyInfo certPublicKey,
      X500Name subject,
      BigInteger serial,
      X500Name issuer,
      BigInteger issuerSerial,
      Duration validity,
      PrivateKey privateKey,
      SignatureAlgorithm sigAlg,
      boolean isCA) {

    try {
      var now = Instant.now();

      var certBuilder =
          new X509v3CertificateBuilder(
              issuer,
              serial,
              new Date(now.toEpochMilli()),
              new Date(now.plus(validity).toEpochMilli()),
              subject,
              certPublicKey);

      certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(isCA));

      var csBuilder = new JcaContentSignerBuilder(sigAlg.getAlgorithmName());
      ContentSigner signer = csBuilder.setProvider(provider).build(privateKey);
      X509CertificateHolder certHolder = certBuilder.build(signer);

      return new JcaX509CertificateConverter().setProvider(provider).getCertificate(certHolder);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
