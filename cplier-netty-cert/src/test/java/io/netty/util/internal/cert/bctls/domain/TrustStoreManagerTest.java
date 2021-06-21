package io.netty.util.internal.cert.bctls.domain;

import io.netty.util.internal.cert.bctls.api.CertificateInfo;
import io.netty.util.internal.cert.bctls.domain.KeyPairManager.Algorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.*;

import static java.time.Duration.ofHours;
import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class TrustStoreManagerTest {

  @TempDir Path tempFolder;

  private final BouncyCastleProvider provider = new BouncyCastleProvider();
  private final SecureRandom secureRandom = new SecureRandom();

  private KeyPairManager keyPairManager;
  private CertificateGenerator certificateGenerator;

  @BeforeEach
  void setUp() {
    keyPairManager = new KeyPairManager(tempFolder, provider, secureRandom);
    certificateGenerator = new CertificateGenerator(provider, secureRandom);
  }

  @Test
  void testCreateTrustStore() {

    TrustStoreManager tsm = new TrustStoreManager(tempFolder, provider, secureRandom);

    KeyPair keyPair = keyPairManager.newKeyPair("TEST", Algorithm.EC, 384);

    KeyPair keyPair2 = keyPairManager.newKeyPair("TEST2", Algorithm.RSA, 2048);

    Certificate certificate =
        certificateGenerator.generateRootCertificate(keyPair, "TEST_CERT", ofHours(1));
    Certificate certificate2 =
        certificateGenerator.generateRootCertificate(keyPair2, "TEST_CERT2", ofHours(1));

    assertTrue(tsm.listTrustStores().isEmpty());

    tsm.createTrustStore("TEST_STORE", asList(certificate, certificate2));

    Map<String, Collection<CertificateInfo>> stores = tsm.listTrustStores();
    assertEquals(1, stores.size());

    Collection<CertificateInfo> info = stores.get("TEST_STORE");
    assertNotNull(info);
    assertEquals(2, info.size());

    List<CertificateInfo> list = new ArrayList<>(info);

    list.sort(Comparator.comparing(a -> a.getAlias()));

    assertEquals("TEST_CERT".toLowerCase(), list.get(0).getAlias());
    assertEquals("TEST_CERT", list.get(0).getSubject());
    assertEquals(keyPair.getPublic().getAlgorithm(), list.get(0).getAlgorithm());
    assertArrayEquals(keyPair.getPublic().getEncoded(), list.get(0).getPublicKey());

    assertEquals("TEST_CERT2".toLowerCase(), list.get(1).getAlias());
    assertEquals("TEST_CERT2", list.get(1).getSubject());
    assertEquals(keyPair2.getPublic().getAlgorithm(), list.get(1).getAlgorithm());
    assertArrayEquals(keyPair2.getPublic().getEncoded(), list.get(1).getPublicKey());
  }

  @Test
  void testAddAndRemoveTrustStoreCerts() throws IOException {

    TrustStoreManager tsm = new TrustStoreManager(tempFolder, provider, secureRandom);

    KeyPair keyPair = keyPairManager.newKeyPair("TEST", Algorithm.EC, 384);

    KeyPair keyPair2 = keyPairManager.newKeyPair("TEST2", Algorithm.RSA, 2048);

    Certificate certificate =
        certificateGenerator.generateRootCertificate(keyPair, "TEST_CERT", ofHours(1));
    Certificate certificate2 =
        certificateGenerator.generateRootCertificate(keyPair2, "TEST_CERT2", ofHours(1));

    assertTrue(tsm.listTrustStores().isEmpty());

    tsm.createTrustStore("TEST_STORE", Collections.singletonList(certificate));

    Map<String, Collection<CertificateInfo>> stores = tsm.listTrustStores();
    assertEquals(1, stores.size());

    Collection<CertificateInfo> info = stores.get("TEST_STORE");
    assertNotNull(info);
    assertEquals(1, info.size());

    List<CertificateInfo> list = new ArrayList<>(info);

    assertEquals("TEST_CERT".toLowerCase(), list.get(0).getAlias());
    assertEquals("TEST_CERT", list.get(0).getSubject());
    assertEquals(keyPair.getPublic().getAlgorithm(), list.get(0).getAlgorithm());
    assertArrayEquals(keyPair.getPublic().getEncoded(), list.get(0).getPublicKey());

    // Add a new cert

    StringWriter writer = new StringWriter();
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      pemWriter.writeObject(certificate2);
      pemWriter.flush();
      pemWriter.close();
    }

    tsm.addTrustedCertificates("TEST_STORE", writer.toString());

    stores = tsm.listTrustStores();
    assertEquals(1, stores.size());

    info = stores.get("TEST_STORE");
    assertNotNull(info);
    assertEquals(2, info.size());

    list = new ArrayList<>(info);

    list.sort(Comparator.comparing(CertificateInfo::getAlias));

    assertEquals("TEST_CERT".toLowerCase(), list.get(0).getAlias());
    assertEquals("TEST_CERT", list.get(0).getSubject());
    assertEquals(keyPair.getPublic().getAlgorithm(), list.get(0).getAlgorithm());
    assertArrayEquals(keyPair.getPublic().getEncoded(), list.get(0).getPublicKey());

    assertEquals("TEST_CERT2".toLowerCase(), list.get(1).getAlias());
    assertEquals("TEST_CERT2", list.get(1).getSubject());
    assertEquals(keyPair2.getPublic().getAlgorithm(), list.get(1).getAlgorithm());
    assertArrayEquals(keyPair2.getPublic().getEncoded(), list.get(1).getPublicKey());

    // Remove the original cert

    tsm.removeTrustedCertificate("TEST_STORE", "TEST_CERT");

    stores = tsm.listTrustStores();
    assertEquals(1, stores.size());

    info = stores.get("TEST_STORE");
    assertNotNull(info);
    assertEquals(1, info.size());

    list = new ArrayList<>(info);

    assertEquals("TEST_CERT2".toLowerCase(), list.get(0).getAlias());
    assertEquals("TEST_CERT2", list.get(0).getSubject());
    assertEquals(keyPair2.getPublic().getAlgorithm(), list.get(0).getAlgorithm());
    assertArrayEquals(keyPair2.getPublic().getEncoded(), list.get(0).getPublicKey());
  }
}
