package io.netty.util.internal.cert.jsse;

import io.netty.util.internal.cert.exception.SslException;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.spec.*;
import java.util.*;
import java.util.function.Supplier;

/** @author galudisu */
final class PemUtils {

  private static final String PKCS1_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
  private static final String PKCS1_FOOTER = "-----END RSA PRIVATE KEY-----";
  private static final String OPENSSL_DSA_HEADER = "-----BEGIN DSA PRIVATE KEY-----";
  private static final String OPENSSL_DSA_FOOTER = "-----END DSA PRIVATE KEY-----";
  private static final String OPENSSL_DSA_PARAMS_HEADER = "-----BEGIN DSA PARAMETERS-----";
  private static final String OPENSSL_DSA_PARAMS_FOOTER = "-----END DSA PARAMETERS-----";
  private static final String PKCS8_HEADER = "-----BEGIN PRIVATE KEY-----";
  private static final String PKCS8_FOOTER = "-----END PRIVATE KEY-----";
  private static final String PKCS8_ENCRYPTED_HEADER = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
  private static final String PKCS8_ENCRYPTED_FOOTER = "-----END ENCRYPTED PRIVATE KEY-----";
  private static final String OPENSSL_EC_HEADER = "-----BEGIN EC PRIVATE KEY-----";
  private static final String OPENSSL_EC_FOOTER = "-----END EC PRIVATE KEY-----";
  private static final String OPENSSL_EC_PARAMS_HEADER = "-----BEGIN EC PARAMETERS-----";
  private static final String OPENSSL_EC_PARAMS_FOOTER = "-----END EC PARAMETERS-----";
  private static final String HEADER = "-----BEGIN";

  private PemUtils() {
    throw new IllegalStateException("Utility class should not be instantiated");
  }

  static PrivateKey readPrivateKeyStream(InputStream keyStream, Supplier<char[]> passwordSupplier) {
    try (BufferedReader bReader =
        new BufferedReader(new InputStreamReader(keyStream, StandardCharsets.UTF_8))) {
      String line = bReader.readLine();
      while (null != line && !line.startsWith(HEADER)) {
        line = bReader.readLine();
      }
      if (null == line) {
        throw new SslException("Error parsing private key, stream is empty");
      }
      switch (line.trim()) {
        case PKCS8_ENCRYPTED_HEADER:
          char[] password = passwordSupplier.get();
          if (password == null) {
            throw new SslException("cannot read encrypted key without a password");
          }
          return parsePKCS8Encrypted(bReader, password);
        case PKCS8_HEADER:
          return parsePKCS8(bReader);
        case PKCS1_HEADER:
          return parsePKCS1Rsa(bReader, passwordSupplier);
        case OPENSSL_DSA_HEADER:
          return parseOpenSslDsa(bReader, passwordSupplier);
        case OPENSSL_DSA_PARAMS_HEADER:
          return parseOpenSslDsa(removeDsaHeaders(bReader), passwordSupplier);
        case OPENSSL_EC_HEADER:
          return parseOpenSslEC(bReader, passwordSupplier);
        case OPENSSL_EC_PARAMS_HEADER:
          return parseOpenSslEC(removeECHeaders(bReader), passwordSupplier);
        default:
          throw new SslException(
              "error parsing Private Key does not contain a supported key format");
      }

    } catch (FileNotFoundException | NoSuchFileException e) {
      throw new SslException("private key stream does not exist", e);
    } catch (IOException | GeneralSecurityException e) {
      throw new SslException("private key stream cannot be parsed", e);
    }
  }

  /**
   * Creates a {@link PrivateKey} from the contents of a file. Supports PKCS#1, PKCS#8 encoded
   * formats of encrypted and plaintext RSA, DSA and EC(secp256r1) keys
   *
   * @param keyPath the path for the key file
   * @param passwordSupplier A password supplier for the potentially encrypted (password protected)
   *     key
   * @return a private key from the contents of the file
   */
  static PrivateKey readPrivateKey(Path keyPath, Supplier<char[]> passwordSupplier) {
    try (BufferedReader bReader = Files.newBufferedReader(keyPath, StandardCharsets.UTF_8)) {
      String line = bReader.readLine();
      while (null != line && !line.startsWith(HEADER)) {
        line = bReader.readLine();
      }
      if (null == line) {
        throw new SslException(
            "Error parsing Private Key [" + keyPath.toAbsolutePath() + "], file is empty");
      }
      switch (line.trim()) {
        case PKCS8_ENCRYPTED_HEADER:
          char[] password = passwordSupplier.get();
          if (password == null) {
            throw new SslException(
                "cannot read encrypted key ["
                    + keyPath.toAbsolutePath()
                    + "] "
                    + "without a password");
          }
          return parsePKCS8Encrypted(bReader, password);
        case PKCS8_HEADER:
          return parsePKCS8(bReader);
        case PKCS1_HEADER:
          return parsePKCS1Rsa(bReader, passwordSupplier);
        case OPENSSL_DSA_HEADER:
          return parseOpenSslDsa(bReader, passwordSupplier);
        case OPENSSL_DSA_PARAMS_HEADER:
          return parseOpenSslDsa(removeDsaHeaders(bReader), passwordSupplier);
        case OPENSSL_EC_HEADER:
          return parseOpenSslEC(bReader, passwordSupplier);
        case OPENSSL_EC_PARAMS_HEADER:
          return parseOpenSslEC(removeECHeaders(bReader), passwordSupplier);
        default:
          throw new SslException(
              "error parsing Private Key ["
                  + keyPath.toAbsolutePath()
                  + "], file "
                  + "does not contain a supported key format");
      }
    } catch (FileNotFoundException | NoSuchFileException e) {
      throw new SslException(
          "private key file [" + keyPath.toAbsolutePath() + "] does not exist", e);
    } catch (IOException | GeneralSecurityException e) {
      throw new SslException(
          "private key file [" + keyPath.toAbsolutePath() + "] cannot be parsed", e);
    }
  }

  /**
   * Removes the EC Headers that OpenSSL adds to EC private keys as the information in them is
   * redundant
   *
   * @throws IOException if the EC Parameter footer is missing
   */
  private static BufferedReader removeECHeaders(BufferedReader bReader) throws IOException {
    String line = bReader.readLine();
    while (line != null) {
      if (OPENSSL_EC_PARAMS_FOOTER.equals(line.trim())) {
        break;
      }
      line = bReader.readLine();
    }
    if (null == line) {
      throw new IOException("Malformed PEM file, EC Parameters footer is missing");
    }
    // Verify that the key starts with the correct header before passing it to parseOpenSslEC
    if (!OPENSSL_EC_HEADER.equals(bReader.readLine())) {
      throw new IOException("Malformed PEM file, EC Key header is missing");
    }
    return bReader;
  }

  /**
   * Removes the DSA Params Headers that OpenSSL adds to DSA private keys as the information in them
   * is redundant
   *
   * @throws IOException if the EC Parameter footer is missing
   */
  private static BufferedReader removeDsaHeaders(BufferedReader bReader) throws IOException {
    String line = bReader.readLine();
    while (line != null) {
      if (OPENSSL_DSA_PARAMS_FOOTER.equals(line.trim())) {
        break;
      }
      line = bReader.readLine();
    }
    if (null == line) {
      throw new IOException("Malformed PEM file, DSA Parameters footer is missing");
    }
    // Verify that the key starts with the correct header before passing it to parseOpenSslDsa
    if (!OPENSSL_DSA_HEADER.equals(bReader.readLine())) {
      throw new IOException("Malformed PEM file, DSA Key header is missing");
    }
    return bReader;
  }

  /**
   * Creates a {@link PrivateKey} from the contents of {@code bReader} that contains an plaintext
   * private key encoded in PKCS#8
   *
   * @param bReader the {@link BufferedReader} containing the key file contents
   * @return {@link PrivateKey}
   * @throws IOException if the file can't be read
   * @throws GeneralSecurityException if the private key can't be generated from the {@link
   *     PKCS8EncodedKeySpec}
   */
  private static PrivateKey parsePKCS8(BufferedReader bReader)
      throws IOException, GeneralSecurityException {
    StringBuilder sb = new StringBuilder();
    String line = bReader.readLine();
    while (line != null) {
      if (PKCS8_FOOTER.equals(line.trim())) {
        break;
      }
      sb.append(line.trim());
      line = bReader.readLine();
    }
    if (null == line) {
      throw new IOException("Malformed PEM file, PEM footer is invalid or missing");
    }
    byte[] keyBytes = Base64.getDecoder().decode(sb.toString());
    String keyAlgo = getKeyAlgorithmIdentifier(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance(keyAlgo);
    return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
  }

  /**
   * Creates a {@link PrivateKey} from the contents of {@code bReader} that contains an EC private
   * key encoded in OpenSSL traditional format.
   *
   * @param bReader the {@link BufferedReader} containing the key file contents
   * @param passwordSupplier A password supplier for the potentially encrypted (password protected)
   *     key
   * @return {@link PrivateKey}
   * @throws IOException if the file can't be read
   * @throws GeneralSecurityException if the private key can't be generated from the {@link
   *     ECPrivateKeySpec}
   */
  private static PrivateKey parseOpenSslEC(
      BufferedReader bReader, Supplier<char[]> passwordSupplier)
      throws IOException, GeneralSecurityException {
    StringBuilder sb = new StringBuilder();
    String line = bReader.readLine();
    Map<String, String> pemHeaders = new HashMap<>();
    while (line != null) {
      if (OPENSSL_EC_FOOTER.equals(line.trim())) {
        break;
      }
      // Parse PEM headers according to https://www.ietf.org/rfc/rfc1421.txt
      if (line.contains(":")) {
        String[] header = line.split(":");
        pemHeaders.put(header[0].trim(), header[1].trim());
      } else {
        sb.append(line.trim());
      }
      line = bReader.readLine();
    }
    if (null == line) {
      throw new IOException("Malformed PEM file, PEM footer is invalid or missing");
    }
    byte[] keyBytes = possiblyDecryptPKCS1Key(pemHeaders, sb.toString(), passwordSupplier);
    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    ECPrivateKeySpec ecSpec = parseEcDer(keyBytes);
    return keyFactory.generatePrivate(ecSpec);
  }

  /**
   * Creates a {@link PrivateKey} from the contents of {@code bReader} that contains an RSA private
   * key encoded in OpenSSL traditional format.
   *
   * @param bReader the {@link BufferedReader} containing the key file contents
   * @param passwordSupplier A password supplier for the potentially encrypted (password protected)
   *     key
   * @return {@link PrivateKey}
   * @throws IOException if the file can't be read
   * @throws GeneralSecurityException if the private key can't be generated from the {@link
   *     RSAPrivateCrtKeySpec}
   */
  private static PrivateKey parsePKCS1Rsa(BufferedReader bReader, Supplier<char[]> passwordSupplier)
      throws IOException, GeneralSecurityException {
    StringBuilder sb = new StringBuilder();
    String line = bReader.readLine();
    Map<String, String> pemHeaders = new HashMap<>();

    while (line != null) {
      if (PKCS1_FOOTER.equals(line.trim())) {
        // Unencrypted
        break;
      }
      // Parse PEM headers according to https://www.ietf.org/rfc/rfc1421.txt
      if (line.contains(":")) {
        String[] header = line.split(":");
        pemHeaders.put(header[0].trim(), header[1].trim());
      } else {
        sb.append(line.trim());
      }
      line = bReader.readLine();
    }
    if (null == line) {
      throw new IOException("Malformed PEM file, PEM footer is invalid or missing");
    }
    byte[] keyBytes = possiblyDecryptPKCS1Key(pemHeaders, sb.toString(), passwordSupplier);
    RSAPrivateCrtKeySpec spec = parseRsaDer(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return keyFactory.generatePrivate(spec);
  }

  /**
   * Creates a {@link PrivateKey} from the contents of {@code bReader} that contains an DSA private
   * key encoded in OpenSSL traditional format.
   *
   * @param bReader the {@link BufferedReader} containing the key file contents
   * @param passwordSupplier A password supplier for the potentially encrypted (password protected)
   *     key
   * @return {@link PrivateKey}
   * @throws IOException if the file can't be read
   * @throws GeneralSecurityException if the private key can't be generated from the {@link
   *     DSAPrivateKeySpec}
   */
  private static PrivateKey parseOpenSslDsa(
      BufferedReader bReader, Supplier<char[]> passwordSupplier)
      throws IOException, GeneralSecurityException {
    StringBuilder sb = new StringBuilder();
    String line = bReader.readLine();
    Map<String, String> pemHeaders = new HashMap<>();

    while (line != null) {
      if (OPENSSL_DSA_FOOTER.equals(line.trim())) {
        // Unencrypted
        break;
      }
      // Parse PEM headers according to https://www.ietf.org/rfc/rfc1421.txt
      if (line.contains(":")) {
        String[] header = line.split(":");
        pemHeaders.put(header[0].trim(), header[1].trim());
      } else {
        sb.append(line.trim());
      }
      line = bReader.readLine();
    }
    if (null == line) {
      throw new IOException("Malformed PEM file, PEM footer is invalid or missing");
    }
    byte[] keyBytes = possiblyDecryptPKCS1Key(pemHeaders, sb.toString(), passwordSupplier);
    DSAPrivateKeySpec spec = parseDsaDer(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("DSA");
    return keyFactory.generatePrivate(spec);
  }

  /**
   * Creates a {@link PrivateKey} from the contents of {@code bReader} that contains an encrypted
   * private key encoded in PKCS#8
   *
   * @param bReader the {@link BufferedReader} containing the key file contents
   * @param keyPassword The password for the encrypted (password protected) key
   * @return {@link PrivateKey}
   * @throws IOException if the file can't be read
   * @throws GeneralSecurityException if the private key can't be generated from the {@link
   *     PKCS8EncodedKeySpec}
   */
  private static PrivateKey parsePKCS8Encrypted(BufferedReader bReader, char[] keyPassword)
      throws IOException, GeneralSecurityException {
    StringBuilder sb = new StringBuilder();
    String line = bReader.readLine();
    while (line != null) {
      if (PKCS8_ENCRYPTED_FOOTER.equals(line.trim())) {
        break;
      }
      sb.append(line.trim());
      line = bReader.readLine();
    }
    if (null == line) {
      throw new IOException("Malformed PEM file, PEM footer is invalid or missing");
    }
    byte[] keyBytes = Base64.getDecoder().decode(sb.toString());

    EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(keyBytes);
    SecretKeyFactory secretKeyFactory =
        SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
    SecretKey secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(keyPassword));
    Arrays.fill(keyPassword, '\u0000');
    Cipher cipher = Cipher.getInstance(encryptedPrivateKeyInfo.getAlgName());
    cipher.init(Cipher.DECRYPT_MODE, secretKey, encryptedPrivateKeyInfo.getAlgParameters());
    PKCS8EncodedKeySpec keySpec = encryptedPrivateKeyInfo.getKeySpec(cipher);
    String keyAlgo = getKeyAlgorithmIdentifier(keySpec.getEncoded());
    KeyFactory keyFactory = KeyFactory.getInstance(keyAlgo);
    return keyFactory.generatePrivate(keySpec);
  }

  /**
   * Decrypts the password protected contents using the algorithm and IV that is specified in the
   * PEM Headers of the file
   *
   * @param pemHeaders The Proc-Type and DEK-Info PEM headers that have been extracted from the key
   *     file
   * @param keyContents The key as a base64 encoded String
   * @param passwordSupplier A password supplier for the encrypted (password protected) key
   * @return the decrypted key bytes
   * @throws GeneralSecurityException if the key can't be decrypted
   * @throws IOException if the PEM headers are missing or malformed
   */
  private static byte[] possiblyDecryptPKCS1Key(
      Map<String, String> pemHeaders, String keyContents, Supplier<char[]> passwordSupplier)
      throws GeneralSecurityException, IOException {
    byte[] keyBytes = Base64.getDecoder().decode(keyContents);
    String procType = pemHeaders.get("Proc-Type");
    if ("4,ENCRYPTED".equals(procType)) {
      // We only handle PEM encryption
      String encryptionParameters = pemHeaders.get("DEK-Info");
      if (null == encryptionParameters) {
        // malformed pem
        throw new IOException("Malformed PEM File, DEK-Info header is missing");
      }
      char[] password = passwordSupplier.get();
      if (password == null) {
        throw new IOException("cannot read encrypted key without a password");
      }
      Cipher cipher = getCipherFromParameters(encryptionParameters, password);
      return cipher.doFinal(keyBytes);
    }
    return keyBytes;
  }

  /**
   * Creates a {@link Cipher} from the contents of the DEK-Info header of a PEM file. RFC 1421
   * indicates that supported algorithms are defined in RFC 1423. RFC 1423 only defines DES-CBS and
   * triple DES (EDE) in CBC mode. AES in CBC mode is also widely used though ( 3 different variants
   * of 128, 192, 256 bit keys )
   *
   * @param dekHeaderValue The value of the DEK-Info PEM header
   * @param password The password with which the key is encrypted
   * @return a cipher of the appropriate algorithm and parameters to be used for decryption
   * @throws GeneralSecurityException if the algorithm is not available in the used security
   *     provider, or if the key is inappropriate for the cipher
   * @throws IOException if the DEK-Info PEM header is invalid
   */
  private static Cipher getCipherFromParameters(String dekHeaderValue, char[] password)
      throws GeneralSecurityException, IOException {
    final String padding = "PKCS5Padding";
    final SecretKey encryptionKey;
    final String[] valueTokens = dekHeaderValue.split(",");
    if (valueTokens.length != 2) {
      throw new IOException("Malformed PEM file, DEK-Info PEM header is invalid");
    }
    final String algorithm = valueTokens[0];
    final String ivString = valueTokens[1];
    final byte[] iv;
    try {
      iv = hexStringToByteArray(ivString);
    } catch (IllegalArgumentException e) {
      throw new IOException("Malformed PEM file, DEK-Info IV is invalid", e);
    }
    if ("DES-CBC".equals(algorithm)) {
      byte[] key = generateOpenSslKey(password, iv, 8);
      encryptionKey = new SecretKeySpec(key, "DES");
    } else if ("DES-EDE3-CBC".equals(algorithm)) {
      byte[] key = generateOpenSslKey(password, iv, 24);
      encryptionKey = new SecretKeySpec(key, "DESede");
    } else if ("AES-128-CBC".equals(algorithm)) {
      byte[] key = generateOpenSslKey(password, iv, 16);
      encryptionKey = new SecretKeySpec(key, "AES");
    } else if ("AES-192-CBC".equals(algorithm)) {
      byte[] key = generateOpenSslKey(password, iv, 24);
      encryptionKey = new SecretKeySpec(key, "AES");
    } else if ("AES-256-CBC".equals(algorithm)) {
      byte[] key = generateOpenSslKey(password, iv, 32);
      encryptionKey = new SecretKeySpec(key, "AES");
    } else {
      throw new GeneralSecurityException(
          "Private Key encrypted with unsupported algorithm [" + algorithm + "]");
    }
    String transformation = encryptionKey.getAlgorithm() + "/" + "CBC" + "/" + padding;
    Cipher cipher = Cipher.getInstance(transformation);
    cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
    return cipher;
  }

  /**
   * Performs key stretching in the same manner that OpenSSL does. This is basically a KDF that uses
   * n rounds of salted MD5 (as many times as needed to get the necessary number of key bytes)
   *
   * <p>https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_PrivateKey_traditional.html
   */
  private static byte[] generateOpenSslKey(char[] password, byte[] salt, int keyLength) {
    byte[] passwordBytes = toUtf8Bytes(password);
    try {
      MessageDigest md5 = MessageDigest.getInstance("md5");
      byte[] key = new byte[keyLength];
      int copied = 0;
      int remaining;
      while (copied < keyLength) {
        remaining = keyLength - copied;
        md5.update(passwordBytes, 0, passwordBytes.length);
        md5.update(salt, 0, 8); // AES IV (salt) is longer but we only need 8 bytes
        byte[] tempDigest = md5.digest();
        int bytesToCopy = Math.min(remaining, 16); // MD5 digests are 16 bytes
        System.arraycopy(tempDigest, 0, key, copied, bytesToCopy);
        copied += bytesToCopy;
        if (remaining == 0) {
          break;
        }
        md5.update(tempDigest, 0, 16); // use previous round digest as IV
      }
      Arrays.fill(passwordBytes, (byte) 0);
      return key;
    } catch (NoSuchAlgorithmException e) {
      throw new SslException(
          "unexpected exception creating MessageDigest instance for [md5]", e);
    }
  }

  public static byte[] toUtf8Bytes(char[] chars) {
    final CharBuffer charBuffer = CharBuffer.wrap(chars);
    final ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
    final byte[] bytes;
    if (byteBuffer.hasArray()) {
      // there is no guarantee that the byte buffers backing array is the right size
      // so we need to make a copy
      bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
      Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
    } else {
      final int length = byteBuffer.limit() - byteBuffer.position();
      bytes = new byte[length];
      byteBuffer.get(bytes);
      // if the buffer is not read only we can reset and fill with 0's
      if (!byteBuffer.isReadOnly()) {
        byteBuffer.clear(); // reset
        for (int i = 0; i < byteBuffer.limit(); i++) {
          byteBuffer.put((byte) 0);
        }
      }
    }
    return bytes;
  }

  /** Converts a hexadecimal string to a byte array */
  private static byte[] hexStringToByteArray(String hexString) {
    int len = hexString.length();
    if (len % 2 == 0) {
      byte[] data = new byte[len / 2];
      for (int i = 0; i < len; i += 2) {
        final int k = Character.digit(hexString.charAt(i), 16);
        final int l = Character.digit(hexString.charAt(i + 1), 16);
        if (k == -1 || l == -1) {
          throw new IllegalStateException("String [" + hexString + "] is not hexadecimal");
        }
        data[i / 2] = (byte) ((k << 4) + l);
      }
      return data;
    } else {
      throw new IllegalStateException(
          "Hexadecimal string ["
              + hexString
              + "] has odd length and cannot be converted to a byte array");
    }
  }

  /**
   * Parses a DER encoded EC key to an {@link ECPrivateKeySpec} using a minimal {@link DerParser}
   *
   * @param keyBytes the private key raw bytes
   * @return {@link ECPrivateKeySpec}
   * @throws IOException if the DER encoded key can't be parsed
   */
  private static ECPrivateKeySpec parseEcDer(byte[] keyBytes)
      throws IOException, GeneralSecurityException {
    DerParser parser = new DerParser(keyBytes);
    DerParser.Asn1Object sequence = parser.readAsn1Object();
    parser = sequence.getParser();
    parser.readAsn1Object().getInteger(); // version
    String keyHex = parser.readAsn1Object().getString();
    BigInteger privateKeyInt = new BigInteger(keyHex, 16);
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
    AlgorithmParameterSpec prime256v1ParamSpec = new ECGenParameterSpec("secp256r1");
    keyPairGenerator.initialize(prime256v1ParamSpec);
    ECParameterSpec parameterSpec =
        ((ECKey) keyPairGenerator.generateKeyPair().getPrivate()).getParams();
    return new ECPrivateKeySpec(privateKeyInt, parameterSpec);
  }

  /**
   * Parses a DER encoded RSA key to a {@link RSAPrivateCrtKeySpec} using a minimal {@link
   * DerParser}
   *
   * @param keyBytes the private key raw bytes
   * @return {@link RSAPrivateCrtKeySpec}
   * @throws IOException if the DER encoded key can't be parsed
   */
  private static RSAPrivateCrtKeySpec parseRsaDer(byte[] keyBytes) throws IOException {
    DerParser parser = new DerParser(keyBytes);
    DerParser.Asn1Object sequence = parser.readAsn1Object();
    parser = sequence.getParser();
    parser
        .readAsn1Object()
        .getInteger(); // (version) We don't need it but must read to get to modulus
    BigInteger modulus = parser.readAsn1Object().getInteger();
    BigInteger publicExponent = parser.readAsn1Object().getInteger();
    BigInteger privateExponent = parser.readAsn1Object().getInteger();
    BigInteger prime1 = parser.readAsn1Object().getInteger();
    BigInteger prime2 = parser.readAsn1Object().getInteger();
    BigInteger exponent1 = parser.readAsn1Object().getInteger();
    BigInteger exponent2 = parser.readAsn1Object().getInteger();
    BigInteger coefficient = parser.readAsn1Object().getInteger();
    return new RSAPrivateCrtKeySpec(
        modulus,
        publicExponent,
        privateExponent,
        prime1,
        prime2,
        exponent1,
        exponent2,
        coefficient);
  }

  /**
   * Parses a DER encoded DSA key to a {@link DSAPrivateKeySpec} using a minimal {@link DerParser}
   *
   * @param keyBytes the private key raw bytes
   * @return {@link DSAPrivateKeySpec}
   * @throws IOException if the DER encoded key can't be parsed
   */
  private static DSAPrivateKeySpec parseDsaDer(byte[] keyBytes) throws IOException {
    DerParser parser = new DerParser(keyBytes);
    DerParser.Asn1Object sequence = parser.readAsn1Object();
    parser = sequence.getParser();
    parser.readAsn1Object().getInteger(); // (version) We don't need it but must read to get to p
    BigInteger p = parser.readAsn1Object().getInteger();
    BigInteger q = parser.readAsn1Object().getInteger();
    BigInteger g = parser.readAsn1Object().getInteger();
    parser.readAsn1Object().getInteger(); // we don't need x
    BigInteger x = parser.readAsn1Object().getInteger();
    return new DSAPrivateKeySpec(x, p, q, g);
  }

  /**
   * Parses a DER encoded private key and reads its algorithm identifier Object OID.
   *
   * @param keyBytes the private key raw bytes
   * @return A string identifier for the key algorithm (RSA, DSA, or EC)
   * @throws GeneralSecurityException if the algorithm oid that is parsed from ASN.1 is unknown
   * @throws IOException if the DER encoded key can't be parsed
   */
  private static String getKeyAlgorithmIdentifier(byte[] keyBytes)
      throws IOException, GeneralSecurityException {
    DerParser parser = new DerParser(keyBytes);
    DerParser.Asn1Object sequence = parser.readAsn1Object();
    parser = sequence.getParser();
    parser.readAsn1Object().getInteger(); // version
    DerParser.Asn1Object algSequence = parser.readAsn1Object();
    parser = algSequence.getParser();
    String oidString = parser.readAsn1Object().getOid();
    switch (oidString) {
      case "1.2.840.10040.4.1":
        return "DSA";
      case "1.2.840.113549.1.1.1":
        return "RSA";
      case "1.2.840.10045.2.1":
        return "EC";
    }
    throw new GeneralSecurityException(
        "Error parsing key algorithm identifier. Algorithm with OID ["
            + oidString
            + "] is not supported");
  }

  static List<X509Certificate> readCertificates(Collection<Path> certPaths)
      throws CertificateException, IOException {
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    List<X509Certificate> certificates = new ArrayList<>(certPaths.size());
    for (Path path : certPaths) {
      try (InputStream input = Files.newInputStream(path)) {
        final X509Certificate parsed = (X509Certificate) certFactory.generateCertificate(input);
        if (null == parsed) {
          throw new SslException(
              "failed to parse any certificates from [" + path.toAbsolutePath() + "]");
        }
        certificates.add(parsed);
      }
    }
    return certificates;
  }

  static List<X509Certificate> readCertificatesStream(Collection<InputStream> certPaths)
      throws CertificateException {
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    List<X509Certificate> certificates = new ArrayList<>(certPaths.size());
    for (InputStream input : certPaths) {
      final X509Certificate parsed = (X509Certificate) certFactory.generateCertificate(input);
      if (null == parsed) {
        throw new SslException("failed to parse any certificates from stream");
      }
      certificates.add(parsed);
    }
    return certificates;
  }
}
