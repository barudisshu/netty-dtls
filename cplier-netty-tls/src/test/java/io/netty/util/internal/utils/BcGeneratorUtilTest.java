package io.netty.util.internal.utils;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class BcGeneratorUtilTest {
  @TempDir Path tempDir;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void simpleJacTest() throws Exception {
    KeyPairGenerator keyPairGenerator = BcGeneratorUtil.generateKeyPairGenerator();
    BcGeneratorUtil.TimeSlot timeSlot = BcGeneratorUtil.generateTimeSlot(1);

    KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
    X500Name rootCertIssuer = new X500Name("CN=root-cert");
    X500Name issuedCertSubject = new X500Name("CN=issued-cert");

    BcGeneratorUtil.JcaKeyPair rootJcaKeyPair =
        BcGeneratorUtil.generateX509CaChain(rootKeyPair, timeSlot, rootCertIssuer);
    KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();
    // get root cert
    X509Certificate rootCert = rootJcaKeyPair.getX509Certificate();
    // using root cert to generate public key and private key
    BcGeneratorUtil.JcaKeyPair certJcaKeyPair =
        BcGeneratorUtil.generateX509CertificateAndKey(
            rootKeyPair,
            issuedCertKeyPair,
            rootCert,
            rootCertIssuer,
            issuedCertSubject,
            timeSlot,
            "mydomain.local",
            "127.0.0.1");

    assertNotNull(certJcaKeyPair);
    assertNotNull(certJcaKeyPair.getX509Certificate());
    assertNotNull(certJcaKeyPair.getKeyPair().getPrivate());
  }

  @Test
  void simpleBcTest() throws Exception {
    KeyPairGenerator keyPairGenerator = BcGeneratorUtil.generateKeyPairGenerator();
    BcGeneratorUtil.TimeSlot timeSlot = BcGeneratorUtil.generateTimeSlot(1);

    BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

    KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
    X500Name rootCertIssuer = new X500Name("CN=root-cert");
    X500Name issuedCertSubject = new X500Name("CN=issued-cert");

    BcGeneratorUtil.BcKeyPair rootBcKeyPair =
        BcGeneratorUtil.generateBcCaChain(crypto, rootKeyPair, timeSlot, rootCertIssuer);
    KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();
    // get root cert
    Certificate rootCert = rootBcKeyPair.getCertificate();
    // using root cert to generate public key and private key
    BcGeneratorUtil.BcKeyPair certBcKeyPair =
        BcGeneratorUtil.generateBcCertificateAndKey(
            crypto,
            rootKeyPair,
            issuedCertKeyPair,
            rootCert,
            rootCertIssuer,
            issuedCertSubject,
            timeSlot,
            "mydomain.local",
            "127.0.0.1");

    assertNotNull(certBcKeyPair);
    assertNotNull(certBcKeyPair.getCertificate());
    assertNotNull(certBcKeyPair.getPrivateKey());
  }

  @Test
  void simpleBcExpiredTest() throws Exception {
    KeyPairGenerator keyPairGenerator = BcGeneratorUtil.generateKeyPairGenerator();
    BcGeneratorUtil.TimeSlot timeSlot = BcGeneratorUtil.generateTimeSlot(-1);

    BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

    KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
    X500Name rootCertIssuer = new X500Name("CN=root-cert");
    X500Name issuedCertSubject = new X500Name("CN=issued-cert");

    BcGeneratorUtil.BcKeyPair rootBcKeyPair =
        BcGeneratorUtil.generateBcCaChain(crypto, rootKeyPair, timeSlot, rootCertIssuer);
    KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();
    // get root cert
    Certificate rootCert = rootBcKeyPair.getCertificate();
    // using root cert to generate public key and private key
    BcGeneratorUtil.BcKeyPair certBcKeyPair =
        BcGeneratorUtil.generateBcCertificateAndKey(
            crypto,
            rootKeyPair,
            issuedCertKeyPair,
            rootCert,
            rootCertIssuer,
            issuedCertSubject,
            timeSlot,
            "mydomain.local",
            "127.0.0.1");

    assertNotNull(certBcKeyPair);
    assertNotNull(certBcKeyPair.getCertificate());
    assertNotNull(certBcKeyPair.getPrivateKey());

    // convert
    X509Certificate x509Certificate =
        BcGeneratorUtil.bcCertToX509Cert(certBcKeyPair.getCertificate());
    assertNotNull(x509Certificate);

    // check that is expired
    Date endDate = x509Certificate.getNotAfter();
    // current time is after the certificate last date
    assertTrue(new Date().after(endDate));
  }

  @Test
  void simpleCovertTest() throws Exception {
    File pbFile = tempDir.resolve("ca.crt").toFile();
    String content =
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIDDTCCAnagAwIBAgIJANQN5U6iXqI1MA0GCSqGSIb3DQEBCwUAMIGcMQswCQYD\n"
            + "VQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3pob3Ux\n"
            + "FzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMQ8wDQYDVQQLDAZjcGxpZXIxFTATBgNV\n"
            + "BAMMDGVyaWNzc29uLmNvbTEkMCIGCSqGSIb3DQEJARYVZ2FsdWRpc3VAZXJpY3Nz\n"
            + "b24uY29tMCAXDTIxMDcxNTA5MjU0OFoYDzMwMjAxMTE1MDkyNTQ4WjCBnDELMAkG\n"
            + "A1UEBhMCY24xEjAQBgNVBAgMCUd1YW5nZG9uZzESMBAGA1UEBwwJR3Vhbmd6aG91\n"
            + "MRcwFQYDVQQKDA5Fcmljc3NvbiwgSW5jLjEPMA0GA1UECwwGY3BsaWVyMRUwEwYD\n"
            + "VQQDDAxlcmljc3Nvbi5jb20xJDAiBgkqhkiG9w0BCQEWFWdhbHVkaXN1QGVyaWNz\n"
            + "c29uLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA6wJfZ5LSSrpYSmxC\n"
            + "2gAkjiurunpc5txaHxMq2l9JSg4pfT+O0Jmv948WlJZqq9JMIFtrNcCUl2jXjapB\n"
            + "w2eGSST9DjVTV0oX4ez/6bXnItGsJhKJ5dWHk+3ORpu9VR1Tcykg1GGCTqD7vkq7\n"
            + "ngnhfsgo95EEF9p2frqYW4lImFUCAwEAAaNTMFEwHQYDVR0OBBYEFNGUrbAo75iA\n"
            + "XeXkG+J/Eq7vovUYMB8GA1UdIwQYMBaAFNGUrbAo75iAXeXkG+J/Eq7vovUYMA8G\n"
            + "A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAzQamyrVISKfLM0S94lmd\n"
            + "jC/gqmpzfXMo+BaFGSujmZA/ifXqlMHjC0dzdeV4QCVdpfRw8lA6LX8yCEV0Z5AF\n"
            + "A+1CmPk4ERfn4JElz+o/TXTTTWVgbDU4whV5YtB73P2/k+Nn6mTPydml+any6x/V\n"
            + "G59TYIBiSB906gWe67rvAv4=\n"
            + "-----END CERTIFICATE-----\n";
    Files.write(pbFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    var certificate = CertUtil.loadBcCertificateChain(new BcTlsCrypto(new SecureRandom()), pbFile);
    assertNotNull(certificate);
    assertEquals(CertificateType.X509, certificate.getCertificateType());
    // convert
    X509Certificate x509Certificate = BcGeneratorUtil.bcCertToX509Cert(certificate);
    assertNotNull(x509Certificate);
    X509Certificate[] x509Certificates = BcGeneratorUtil.bcCertToX509Certs(certificate);
    assertNotNull(x509Certificates);
  }

  @Test
  void simpleExportTest() throws Exception {
    KeyPairGenerator keyPairGenerator = BcGeneratorUtil.generateKeyPairGenerator();
    BcGeneratorUtil.TimeSlot timeSlot = BcGeneratorUtil.generateTimeSlot(1);

    KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
    X500Name rootCertIssuer = new X500Name("CN=root-cert");
    X500Name issuedCertSubject = new X500Name("CN=issued-cert");
    KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

    Path filePath = tempDir.resolve("target/cert");
    assertTrue(filePath.toFile().mkdirs());

    BcGeneratorUtil.JcaKeyPair rootJcaKeyPair =
        BcGeneratorUtil.exportX509CaChain(
            rootKeyPair, rootCertIssuer, timeSlot, "password", filePath);

    // get root cert
    X509Certificate rootCert = rootJcaKeyPair.getX509Certificate();

    BcGeneratorUtil.JcaKeyPair certJcaKeyPair =
        BcGeneratorUtil.exportCertificate(
            rootKeyPair,
            issuedCertKeyPair,
            rootCert,
            rootCertIssuer,
            issuedCertSubject,
            timeSlot,
            "mydomain.local",
            "127.0.0.1",
            "password",
            filePath);

    assertNotNull(certJcaKeyPair);
    assertNotNull(certJcaKeyPair.getX509Certificate());
    assertNotNull(certJcaKeyPair.getKeyPair().getPrivate());
  }
}
