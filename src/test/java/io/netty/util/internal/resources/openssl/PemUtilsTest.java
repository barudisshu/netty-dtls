//package io.netty.util.internal.resources.openssl;
//
//import org.junit.jupiter.api.Test;
//
//import java.io.InputStream;
//import java.lang.reflect.Constructor;
//import java.lang.reflect.InvocationTargetException;
//import java.lang.reflect.Modifier;
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.security.Key;
//import java.security.KeyStore;
//import java.security.PrivateKey;
//import java.util.function.Supplier;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//class PemUtilsTest {
//
//  private static final Supplier<char[]> EMPTY_PASSWORD = () -> new char[0];
//  private static final Supplier<char[]> TESTNODE_PASSWORD = "testnode"::toCharArray;
//
//  Path getDataPath(String relativePath) {
//    try {
//      return PathUtils.get(getClass().getResource(relativePath).toURI())
//          .toAbsolutePath()
//          .normalize();
//    } catch (Exception e) {
//      throw new RuntimeException("resource not found: " + relativePath, e);
//    }
//  }
//
//  @Test(expected = InvocationTargetException.class)
//  void testPrivateConstructor()
//      throws IllegalAccessException, InstantiationException, NoSuchMethodException,
//          InvocationTargetException {
//    Constructor<PemUtils> constructor = PemUtils.class.getDeclaredConstructor();
//    assertTrue(Modifier.isPrivate(constructor.getModifiers()));
//    constructor.setAccessible(true);
//    constructor.newInstance();
//  }
//
//  @Test
//  void testReadPKCS8RsaKey() throws Exception {
//    Key key = getKeyFromKeystore("RSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/rsa_key_pkcs8_plain.pem"), EMPTY_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadPKCS8RsaKeyWithBagAttrs() throws Exception {
//    Key key = getKeyFromKeystore("RSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/testnode_with_bagattrs.pem"), EMPTY_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadPKCS8DsaKey() throws Exception {
//    Key key = getKeyFromKeystore("DSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/dsa_key_pkcs8_plain.pem"), EMPTY_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadPKCS8EcKey() throws Exception {
//    Key key = getKeyFromKeystore("EC");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/ec_key_pkcs8_plain.pem"), EMPTY_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadEncryptedPKCS8Key() throws Exception {
//    Key key = getKeyFromKeystore("RSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/key_pkcs8_encrypted.pem"), TESTNODE_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test(expected = SslConfigException.class)
//  void testReadEncryptedPKCS8KeyEmptyPassword() throws Exception {
//    Key key = getKeyFromKeystore("RSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PemUtils.readPrivateKey(getDataPath("/certs/key_pkcs8_encrypted.pem"), () -> null);
//  }
//
//  @Test
//  void testReadDESEncryptedPKCS1Key() throws Exception {
//    Key key = getKeyFromKeystore("RSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/testnode.pem"), TESTNODE_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadAESEncryptedPKCS1Key() throws Exception {
//    Key key = getKeyFromKeystore("RSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/testnode-aes128.pem"), TESTNODE_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadAESEncryptedPKCS1Key1() throws Exception {
//    Key key = getKeyFromKeystore("RSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/testnode-aes192.pem"), TESTNODE_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadAESEncryptedPKCS1Key2() throws Exception {
//    Key key = getKeyFromKeystore("RSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/testnode-aes256.pem"), TESTNODE_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadPKCS1RsaKey() throws Exception {
//    Key key = getKeyFromKeystore("RSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/testnode-unprotected.pem"), TESTNODE_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadOpenSslDsaKey() throws Exception {
//    Key key = getKeyFromKeystore("DSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/dsa_key_openssl_plain.pem"), EMPTY_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadOpenSslDsaKeyWithParams() throws Exception {
//    Key key = getKeyFromKeystore("DSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(
//            getDataPath("/certs/dsa_key_openssl_plain_with_params.pem"), EMPTY_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadEncryptedOpenSslDsaKey() throws Exception {
//    Key key = getKeyFromKeystore("DSA");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(
//            getDataPath("/certs/dsa_key_openssl_encrypted.pem"), TESTNODE_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadOpenSslEcKey() throws Exception {
//    Key key = getKeyFromKeystore("EC");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(getDataPath("/certs/ec_key_openssl_plain.pem"), EMPTY_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadOpenSslEcKeyWithParams() throws Exception {
//    Key key = getKeyFromKeystore("EC");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(
//            getDataPath("/certs/ec_key_openssl_plain_with_params.pem"), EMPTY_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test
//  void testReadEncryptedOpenSslEcKey() throws Exception {
//    Key key = getKeyFromKeystore("EC");
//    assertNotNull(key);
//    assertTrue(key instanceof PrivateKey);
//    PrivateKey privateKey =
//        PemUtils.readPrivateKey(
//            getDataPath("/certs/ec_key_openssl_encrypted.pem"), TESTNODE_PASSWORD);
//    assertNotNull(privateKey);
//    assertEquals(privateKey, key);
//  }
//
//  @Test(expected = SslConfigException.class)
//  void testReadUnsupportedKey() {
//    final Path path = getDataPath("/certs/key_unsupported.pem");
//    PemUtils.readPrivateKey(path, TESTNODE_PASSWORD);
//  }
//
//  @Test(expected = SslConfigException.class)
//  void testReadPemCertificateAsKey() {
//    final Path path = getDataPath("/certs/testnode.crt");
//    PemUtils.readPrivateKey(path, TESTNODE_PASSWORD);
//  }
//
//  @Test(expected = SslConfigException.class)
//  void testReadCorruptedKey() {
//    final Path path = getDataPath("/certs/corrupted_key_pkcs8_plain.pem");
//    PemUtils.readPrivateKey(path, TESTNODE_PASSWORD);
//  }
//
//  @Test(expected = SslConfigException.class)
//  void testReadEmptyFile() {
//    final Path path = getDataPath("/certs/empty.pem");
//    PemUtils.readPrivateKey(path, TESTNODE_PASSWORD);
//  }
//
//  private Key getKeyFromKeystore(String algo) throws Exception {
//    Path keystorePath = getDataPath("/certs/testnode.jks");
//    try (InputStream in = Files.newInputStream(keystorePath)) {
//      KeyStore keyStore = KeyStore.getInstance("jks");
//      keyStore.load(in, "testnode".toCharArray());
//      return keyStore.getKey("testnode_" + algo, "testnode".toCharArray());
//    }
//  }
//}
