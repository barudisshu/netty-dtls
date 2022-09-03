package io.netty.util.internal.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.encoders.DecoderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class CertUtilTest {

  @TempDir File tempDir;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    assertTrue(tempDir.isDirectory(), "Should be a directory");
  }

  // openssl genrsa -out ca.key 1024
  @Test
  void loadBcRSAPrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "rsa.key");
    String content =
        "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIICXAIBAAKBgQC2E2WqvTUFNoS89x+ZPtuk73DW1CLPZZVi8d+3uvf58CVDadE6\n"
            + "5MDVMvyXV8uYrwPhO573PlOZyJL5llwntb3V0VPZtTj8i21lUPakgIU3DfyyCBLZ\n"
            + "b10nrJFmBSTs5O2ohIaM1P3sDYeG3ZjejQYmB6dqUmp8WqX8pA7xusqmhwIDAQAB\n"
            + "AoGAJWzhRfI0Vsj5CdqGDTrlbQamnBHowdawmTD8ekidNivNjQjQMBnbJTegwf8S\n"
            + "42R+GKrnpwyRpJec1l64vJTX2yVXR3uon6HJ8Br5xVBluo4KlU4jd0dgGeLjPXpV\n"
            + "tUjgTqeKegimwhiyF6cctgCfI9e1KdtcIy7RDnFXc697HcECQQDsd/m8Tr5GXndO\n"
            + "9gFcMdHdS+y0Y1tknxUU2SHnkxbrKwGmCfv5UpBigo0jjJGQCWP4otXNbflehZkn\n"
            + "NdwtIg3nAkEAxR1O6ug+CKwmaabIKHfAG9Jc6AiOH0dBiD+Q6vpiBb2RVzcTvBbK\n"
            + "kMWIw60SEfb9tuWwMrM5BePRka2aX0FOYQJBAISocePgUQJtMIWNoQm1sURyuaIh\n"
            + "Mz5puIvvnAOsEulvQQeDBmbCmNmK398Xlvm1Ku5re4I5tfH/BQJoRtLTDfUCQHvn\n"
            + "jHAFRNlWvV60RCWMAOp8NYJ1vkDTHdJzgrjyYyOQogfcyz70ZKjUQsAdzroUNC//\n"
            + "+d4k4rddGaMlKWCvQIECQCjBTbFvcMIp76Ano/CN6awzXWbq5jOiNw0S5GYwho5M\n"
            + "ujwwhk/KnwTHQW8+g60lhNXCU2V3x9cjgDYZn7ULHtY=\n"
            + "-----END RSA PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));

    var privateKey = CertUtil.loadBcPrivateKeyResource(pkFile, null);
    assertNotNull(privateKey);
    assertTrue(privateKey.isPrivate());
  }

  @Test
  void loadJcaRSAPrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "rsa.key");
    String content =
        "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIICXAIBAAKBgQC2E2WqvTUFNoS89x+ZPtuk73DW1CLPZZVi8d+3uvf58CVDadE6\n"
            + "5MDVMvyXV8uYrwPhO573PlOZyJL5llwntb3V0VPZtTj8i21lUPakgIU3DfyyCBLZ\n"
            + "b10nrJFmBSTs5O2ohIaM1P3sDYeG3ZjejQYmB6dqUmp8WqX8pA7xusqmhwIDAQAB\n"
            + "AoGAJWzhRfI0Vsj5CdqGDTrlbQamnBHowdawmTD8ekidNivNjQjQMBnbJTegwf8S\n"
            + "42R+GKrnpwyRpJec1l64vJTX2yVXR3uon6HJ8Br5xVBluo4KlU4jd0dgGeLjPXpV\n"
            + "tUjgTqeKegimwhiyF6cctgCfI9e1KdtcIy7RDnFXc697HcECQQDsd/m8Tr5GXndO\n"
            + "9gFcMdHdS+y0Y1tknxUU2SHnkxbrKwGmCfv5UpBigo0jjJGQCWP4otXNbflehZkn\n"
            + "NdwtIg3nAkEAxR1O6ug+CKwmaabIKHfAG9Jc6AiOH0dBiD+Q6vpiBb2RVzcTvBbK\n"
            + "kMWIw60SEfb9tuWwMrM5BePRka2aX0FOYQJBAISocePgUQJtMIWNoQm1sURyuaIh\n"
            + "Mz5puIvvnAOsEulvQQeDBmbCmNmK398Xlvm1Ku5re4I5tfH/BQJoRtLTDfUCQHvn\n"
            + "jHAFRNlWvV60RCWMAOp8NYJ1vkDTHdJzgrjyYyOQogfcyz70ZKjUQsAdzroUNC//\n"
            + "+d4k4rddGaMlKWCvQIECQCjBTbFvcMIp76Ano/CN6awzXWbq5jOiNw0S5GYwho5M\n"
            + "ujwwhk/KnwTHQW8+g60lhNXCU2V3x9cjgDYZn7ULHtY=\n"
            + "-----END RSA PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));

    var privateKey = CertUtil.loadJcaPrivateKeyResource(pkFile, null);
    assertNotNull(privateKey);
    assertEquals("RSA", privateKey.getAlgorithm());
  }

  // private key
  @Test
  void loadBcRSAKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "rsa.key");
    String content =
        "-----BEGIN PRIVATE KEY-----\n"
            + "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALc/VEO9xwkdSIdt\n"
            + "wkg4QJBljFE9htVTTu0L+eXbptx+R+UHH6dPTkJSmOnUIXF4hn8ZpFLkoYNTL3/i\n"
            + "MGrozXFqoRa/OeDKt8sxLrsCnKQqevLQebQ9I1IlCECs66diXh39abhq+wG/iepA\n"
            + "uvtvMA1X9GIAXDjCTUJrrvxk9iRJAgMBAAECgYAd8Mb/2n4uyw4SsqhPzIEgFrd6\n"
            + "fqcNK/N1X8OQ/vagiDGPBj7xw09yHrTFX9enBp5THglvUdPh9TGJn5dxoGAQpR+f\n"
            + "ij4cfTLkKqDpuwoOUwHJxcp/EMqCxt+g0JDlNtHut+9DltTzLzgddLgOIwmOeBpY\n"
            + "Ji2Q4QtJk0M+FUXVUQJBAN9o3gSHkv6mxTf2yJvsy8BH7m3x2cBtD05K7CNbdUUd\n"
            + "W01SQkXHlGR2iWRy6/quqYkyS1x0IfB1IEuv0Y2e8MMCQQDR+p7RIUOtSePkoeVN\n"
            + "EDUN6giBy4njedVn2Pl+VW/NU8EEfCuyDNceLS6ilK/Y7HV1nLD5Qz8c6M5K6jE8\n"
            + "bEYDAkBd/mvycevZcebl7dFnMNBknJ7m6OsZd4kKAqGpGpCTPI+uT16MpzR6tBiI\n"
            + "B4XbGWNA0sU8J6wj09N7pIRA1k8rAkA7GBlSKdZuEnl8gsORqJoFzHOQc8PerQ8O\n"
            + "JtYwY8MPOh78MCXr+gkgiP6y6r2Cgymba/mybOZ6MFq+YqJwqtgZAkBCTAtzc1Zy\n"
            + "cHLS/rrzhsPoho84gZCteffE4Lzcs5WhqW245mQO4AlYUWLusZLdL0hG5pK8AllI\n"
            + "8GwzEsdNvavM\n"
            + "-----END PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));

    var privateKey = CertUtil.loadBcPrivateKeyResource(pkFile, null);
    assertNotNull(privateKey);
    assertTrue(privateKey.isPrivate());
  }

  // private key
  @Test
  void loadJcaRSAKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "rsa.key");
    String content =
        "-----BEGIN PRIVATE KEY-----\n"
            + "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALc/VEO9xwkdSIdt\n"
            + "wkg4QJBljFE9htVTTu0L+eXbptx+R+UHH6dPTkJSmOnUIXF4hn8ZpFLkoYNTL3/i\n"
            + "MGrozXFqoRa/OeDKt8sxLrsCnKQqevLQebQ9I1IlCECs66diXh39abhq+wG/iepA\n"
            + "uvtvMA1X9GIAXDjCTUJrrvxk9iRJAgMBAAECgYAd8Mb/2n4uyw4SsqhPzIEgFrd6\n"
            + "fqcNK/N1X8OQ/vagiDGPBj7xw09yHrTFX9enBp5THglvUdPh9TGJn5dxoGAQpR+f\n"
            + "ij4cfTLkKqDpuwoOUwHJxcp/EMqCxt+g0JDlNtHut+9DltTzLzgddLgOIwmOeBpY\n"
            + "Ji2Q4QtJk0M+FUXVUQJBAN9o3gSHkv6mxTf2yJvsy8BH7m3x2cBtD05K7CNbdUUd\n"
            + "W01SQkXHlGR2iWRy6/quqYkyS1x0IfB1IEuv0Y2e8MMCQQDR+p7RIUOtSePkoeVN\n"
            + "EDUN6giBy4njedVn2Pl+VW/NU8EEfCuyDNceLS6ilK/Y7HV1nLD5Qz8c6M5K6jE8\n"
            + "bEYDAkBd/mvycevZcebl7dFnMNBknJ7m6OsZd4kKAqGpGpCTPI+uT16MpzR6tBiI\n"
            + "B4XbGWNA0sU8J6wj09N7pIRA1k8rAkA7GBlSKdZuEnl8gsORqJoFzHOQc8PerQ8O\n"
            + "JtYwY8MPOh78MCXr+gkgiP6y6r2Cgymba/mybOZ6MFq+YqJwqtgZAkBCTAtzc1Zy\n"
            + "cHLS/rrzhsPoho84gZCteffE4Lzcs5WhqW245mQO4AlYUWLusZLdL0hG5pK8AllI\n"
            + "8GwzEsdNvavM\n"
            + "-----END PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));

    var privateKey = CertUtil.loadJcaPrivateKeyResource(pkFile, null);
    assertNotNull(privateKey);
    assertEquals("RSA", privateKey.getAlgorithm());
  }

  // openssl genrsa -out ca.key -aes128 -passout pass:P@ssw0rd 1024
  @Test
  void loadBcRSAEncryptionPrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "rsa_encryption.key");
    String content =
        "-----BEGIN RSA PRIVATE KEY-----\n"
            + "Proc-Type: 4,ENCRYPTED\n"
            + "DEK-Info: AES-128-CBC,392661B837964DB98C466ED6B092CA55\n"
            + "\n"
            + "alXROHP5tWe6KYmSv3sZfFLxUh/EtMcuf8LB4r0JJGS1Hbg7cSRPLY9XetmTk/nf\n"
            + "FjPwzmWZUf2mYGH6ql5w7WUoTzJ2W1itaZgirdNydi40+wGq70Z4dGT41sNahZ9x\n"
            + "XNEDFQAQPBHdQ0qGdU++muC5I8KRpWRCZcQanzOh/tmfqF0D47qzvUrAbfcGt3Qb\n"
            + "dQjB8wYQcCKLmCd3mk595kdZVQDILqN+xoX3rqJD1JBnvUgHrem/ngdpgASZd4kM\n"
            + "l5elVmicJFgbxdIykVNwT2WA2VCwtxxLgOi0vZIdekKLN4lccEy7THwmuAUjxeWa\n"
            + "TwZA/Q827MpHaycYfRvKox3EhjxtISvCY9E3iOQ85+LHXOc7qwJ6aKWE1cTN6lKo\n"
            + "EZD2wzSXRpswjxTlmdAImVTOodn2JBc+ltO6MNWSgGRsQojMBgc+Gr1SLovEsbuM\n"
            + "xegargVapHewLlOEO0pL7L308sm3x6hi/tOXrQ2Wh7aipUowEBTMIKxgU10Vu2L3\n"
            + "MvzICwzA1NS2mWnWvj5RKQedFsunKmd7pYNJhNwYP2VIeVR27IigSi0+Qlwe9n8j\n"
            + "klLbIFuwliRSezsCMjLK3+Pc01IywLuilBe6lkiBwnI1K1BSMM5B/hZhsgy76QV6\n"
            + "QlcsedkXsnTOC4bbmhSmygU+jwr0N0pYhap1uFmPHrgeB+C2ph7Ny5f25r3KhstR\n"
            + "vb/3twuWdaRypqUanJ02Flb46OOtBIhlMObNVqJ3gOzq4152vXCCxh3+rBmMav29\n"
            + "G5a3JzOEzcFomUFnSijK7U3Mg4OJDFqC/VJcd/WkWSwCBoouJLAydScB+pLZ8emJ\n"
            + "-----END RSA PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));

    var privateKey = CertUtil.loadBcPrivateKeyResource(pkFile, "P@ssw0rd");
    assertNotNull(privateKey);
    assertTrue(privateKey.isPrivate());
  }

  @Test
  void loadJcaRSAEncryptionPrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "rsa_encryption.key");
    String content =
        "-----BEGIN RSA PRIVATE KEY-----\n"
            + "Proc-Type: 4,ENCRYPTED\n"
            + "DEK-Info: AES-128-CBC,392661B837964DB98C466ED6B092CA55\n"
            + "\n"
            + "alXROHP5tWe6KYmSv3sZfFLxUh/EtMcuf8LB4r0JJGS1Hbg7cSRPLY9XetmTk/nf\n"
            + "FjPwzmWZUf2mYGH6ql5w7WUoTzJ2W1itaZgirdNydi40+wGq70Z4dGT41sNahZ9x\n"
            + "XNEDFQAQPBHdQ0qGdU++muC5I8KRpWRCZcQanzOh/tmfqF0D47qzvUrAbfcGt3Qb\n"
            + "dQjB8wYQcCKLmCd3mk595kdZVQDILqN+xoX3rqJD1JBnvUgHrem/ngdpgASZd4kM\n"
            + "l5elVmicJFgbxdIykVNwT2WA2VCwtxxLgOi0vZIdekKLN4lccEy7THwmuAUjxeWa\n"
            + "TwZA/Q827MpHaycYfRvKox3EhjxtISvCY9E3iOQ85+LHXOc7qwJ6aKWE1cTN6lKo\n"
            + "EZD2wzSXRpswjxTlmdAImVTOodn2JBc+ltO6MNWSgGRsQojMBgc+Gr1SLovEsbuM\n"
            + "xegargVapHewLlOEO0pL7L308sm3x6hi/tOXrQ2Wh7aipUowEBTMIKxgU10Vu2L3\n"
            + "MvzICwzA1NS2mWnWvj5RKQedFsunKmd7pYNJhNwYP2VIeVR27IigSi0+Qlwe9n8j\n"
            + "klLbIFuwliRSezsCMjLK3+Pc01IywLuilBe6lkiBwnI1K1BSMM5B/hZhsgy76QV6\n"
            + "QlcsedkXsnTOC4bbmhSmygU+jwr0N0pYhap1uFmPHrgeB+C2ph7Ny5f25r3KhstR\n"
            + "vb/3twuWdaRypqUanJ02Flb46OOtBIhlMObNVqJ3gOzq4152vXCCxh3+rBmMav29\n"
            + "G5a3JzOEzcFomUFnSijK7U3Mg4OJDFqC/VJcd/WkWSwCBoouJLAydScB+pLZ8emJ\n"
            + "-----END RSA PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));

    var privateKey = CertUtil.loadJcaPrivateKeyResource(pkFile, "P@ssw0rd");
    assertNotNull(privateKey);
    assertEquals("RSA", privateKey.getAlgorithm());
  }

  // openssl dsaparam -genkey -out ca.key 1024
  @Test
  void loadBcDSAPrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "dsa.key");
    String content =
        "-----BEGIN DSA PARAMETERS-----\n"
            + "MIIBHgKBgQDt3L0oJh8qL+kxEXtkI6M7yEvwlHas8BV2jRx2+pd2M3nqMP0Ixyre\n"
            + "LmyaaoQA3fKjfkBigTARNA+n5s6ds52OjP7yuE91ad6/uy+ULhlZF2Lem4TeKEiB\n"
            + "yZL+bw3ghAva2t1yM9ENtgaM7kH2YbHu+QO2reyiiVkNwar2xeflswIVAN9hiOuQ\n"
            + "Ytzd5IMZwswFy6Amop5fAoGASSCBySjEU112wIvjMUPnnxk2aDJ9cGhok7BZNjQ2\n"
            + "hm1DnqU3b+W+JlfZqjMsEFf7h5KoYTvJ7KI2WHIN9k+StQKLoszXmbhbeNy0GK3F\n"
            + "ShRdTlu2nWoo8UyYsjc5IVJJ6QBZ8WlMiYtbZ3LpMdpDHftgRVnV+IGlemHeDOuC\n"
            + "dk0=\n"
            + "-----END DSA PARAMETERS-----\n"
            + "-----BEGIN DSA PRIVATE KEY-----\n"
            + "MIIBvAIBAAKBgQDt3L0oJh8qL+kxEXtkI6M7yEvwlHas8BV2jRx2+pd2M3nqMP0I\n"
            + "xyreLmyaaoQA3fKjfkBigTARNA+n5s6ds52OjP7yuE91ad6/uy+ULhlZF2Lem4Te\n"
            + "KEiByZL+bw3ghAva2t1yM9ENtgaM7kH2YbHu+QO2reyiiVkNwar2xeflswIVAN9h\n"
            + "iOuQYtzd5IMZwswFy6Amop5fAoGASSCBySjEU112wIvjMUPnnxk2aDJ9cGhok7BZ\n"
            + "NjQ2hm1DnqU3b+W+JlfZqjMsEFf7h5KoYTvJ7KI2WHIN9k+StQKLoszXmbhbeNy0\n"
            + "GK3FShRdTlu2nWoo8UyYsjc5IVJJ6QBZ8WlMiYtbZ3LpMdpDHftgRVnV+IGlemHe\n"
            + "DOuCdk0CgYEAqmlpagzo5t1ss8F+r9hc1epRAXF6anEBNaQpJszMjCc4NN6vUvWi\n"
            + "wsy1H3HoPw/FiY//5S9PKgh3CJmzIrNBN1CCvHxxTIhl9FrJ1RPXZ8xewd/hOpQ9\n"
            + "vOslqp5YMLXhgGZf0fbyMyM8zmR6tNWTJOtnb30dLgAoExjky38VM2ECFQCT1Ghz\n"
            + "hbQClKNMLzIVF8Coh36Fmg==\n"
            + "-----END DSA PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));

    var privateKey = CertUtil.loadBcPrivateKeyResource(pkFile, null);
    assertNotNull(privateKey);
    assertTrue(privateKey.isPrivate());
  }

  @Test
  void loadJcaDSAPrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "dsa.key");
    String content =
        "-----BEGIN DSA PARAMETERS-----\n"
            + "MIIBHgKBgQDt3L0oJh8qL+kxEXtkI6M7yEvwlHas8BV2jRx2+pd2M3nqMP0Ixyre\n"
            + "LmyaaoQA3fKjfkBigTARNA+n5s6ds52OjP7yuE91ad6/uy+ULhlZF2Lem4TeKEiB\n"
            + "yZL+bw3ghAva2t1yM9ENtgaM7kH2YbHu+QO2reyiiVkNwar2xeflswIVAN9hiOuQ\n"
            + "Ytzd5IMZwswFy6Amop5fAoGASSCBySjEU112wIvjMUPnnxk2aDJ9cGhok7BZNjQ2\n"
            + "hm1DnqU3b+W+JlfZqjMsEFf7h5KoYTvJ7KI2WHIN9k+StQKLoszXmbhbeNy0GK3F\n"
            + "ShRdTlu2nWoo8UyYsjc5IVJJ6QBZ8WlMiYtbZ3LpMdpDHftgRVnV+IGlemHeDOuC\n"
            + "dk0=\n"
            + "-----END DSA PARAMETERS-----\n"
            + "-----BEGIN DSA PRIVATE KEY-----\n"
            + "MIIBvAIBAAKBgQDt3L0oJh8qL+kxEXtkI6M7yEvwlHas8BV2jRx2+pd2M3nqMP0I\n"
            + "xyreLmyaaoQA3fKjfkBigTARNA+n5s6ds52OjP7yuE91ad6/uy+ULhlZF2Lem4Te\n"
            + "KEiByZL+bw3ghAva2t1yM9ENtgaM7kH2YbHu+QO2reyiiVkNwar2xeflswIVAN9h\n"
            + "iOuQYtzd5IMZwswFy6Amop5fAoGASSCBySjEU112wIvjMUPnnxk2aDJ9cGhok7BZ\n"
            + "NjQ2hm1DnqU3b+W+JlfZqjMsEFf7h5KoYTvJ7KI2WHIN9k+StQKLoszXmbhbeNy0\n"
            + "GK3FShRdTlu2nWoo8UyYsjc5IVJJ6QBZ8WlMiYtbZ3LpMdpDHftgRVnV+IGlemHe\n"
            + "DOuCdk0CgYEAqmlpagzo5t1ss8F+r9hc1epRAXF6anEBNaQpJszMjCc4NN6vUvWi\n"
            + "wsy1H3HoPw/FiY//5S9PKgh3CJmzIrNBN1CCvHxxTIhl9FrJ1RPXZ8xewd/hOpQ9\n"
            + "vOslqp5YMLXhgGZf0fbyMyM8zmR6tNWTJOtnb30dLgAoExjky38VM2ECFQCT1Ghz\n"
            + "hbQClKNMLzIVF8Coh36Fmg==\n"
            + "-----END DSA PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));

    var privateKey = CertUtil.loadJcaPrivateKeyResource(pkFile, null);
    assertNotNull(privateKey);
    assertEquals("DSA", privateKey.getAlgorithm());
  }

  // openssl ecparam -genkey -name secp384r1 -noout -out ca.key
  @Test
  void loadBcECDSAPrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "ecdsa.key");
    String content =
        "-----BEGIN EC PRIVATE KEY-----\n"
            + "MIGkAgEBBDDFa2kKwIrYjDg5pxlNiu9mJdrjrB0P88G+07pf76SwRka5VeptIHOb\n"
            + "Z5/HpKC3oM+gBwYFK4EEACKhZANiAAT00BauqCFjG3QbjfvqqfPM57ARDp0AoiEK\n"
            + "b2yTszVcykxKnuTpbmuagNbdBEFfGmj+tDuC7KvUX+udzWnK1E+X6YmsV101XAgE\n"
            + "LEAXmoxNc6fjNWt9e0ATHi8JKoXi2ZI=\n"
            + "-----END EC PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));

    var privateKey = CertUtil.loadBcPrivateKeyResource(pkFile, null);
    assertNotNull(privateKey);
    assertTrue(privateKey.isPrivate());
  }

  @Test
  void loadJcaECDSAPrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "ecdsa.key");
    String content =
        "-----BEGIN EC PRIVATE KEY-----\n"
            + "MIGkAgEBBDDFa2kKwIrYjDg5pxlNiu9mJdrjrB0P88G+07pf76SwRka5VeptIHOb\n"
            + "Z5/HpKC3oM+gBwYFK4EEACKhZANiAAT00BauqCFjG3QbjfvqqfPM57ARDp0AoiEK\n"
            + "b2yTszVcykxKnuTpbmuagNbdBEFfGmj+tDuC7KvUX+udzWnK1E+X6YmsV101XAgE\n"
            + "LEAXmoxNc6fjNWt9e0ATHi8JKoXi2ZI=\n"
            + "-----END EC PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));

    var privateKey = CertUtil.loadJcaPrivateKeyResource(pkFile, null);
    assertNotNull(privateKey);
    assertEquals("EC", privateKey.getAlgorithm());
  }

  // openssl pkcs8 -topk8 -in rsa.key -out pkcs8.key
  @Test
  void loadBcPKCS8PrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "pkcs8.key");
    String content =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            + "MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI6T6YzPn438ECAggA\n"
            + "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBw5rDy+syhWjH1bSr1wdpsBIIC\n"
            + "gNpW/bVkikKTmDOhtEUe1ipg+IxNMXJ9yUqWvUFu9OeAZw5AAHR/xfM3efV5aLhl\n"
            + "+D28gFaxSeL6ZipDX3MpM1VTc6/4NJgySce3TP1HKwSUBAL7c4q7KCsHQQ5yX3hh\n"
            + "gAHphmnQEPUEDhbPHRZbfvkyaJrv0jzSymLRaTagTa0a8iJoczcjnmf3NQWNe5YU\n"
            + "En/UPa4T3VMgqLDum7DgfmHPjfOwHYD4rdAZv/J/P6wTdBYyPulvW+lhvWftegu0\n"
            + "Xfj7V6TePbxIviU2IP/Yc5mJ+x4iS0V+JmlY2iYVav8mXBZTVgcPFp3/E3+u97DE\n"
            + "rlz5QPSad5hPG5fKyvDfULomQGQSmi2b54vYe2zsPZ7qudm0Q2d3Wbvg9utI3bPf\n"
            + "z4AGcKvuOWA+GFBU/7YtNF1pLFhalkZp4TMrPknrvO4mjg57CMihty5KspsYHu4d\n"
            + "DH/ielmFAQIhJKgD3ts1+nuNIYWFhSu+gNRw3weNd7p8PpcxDPGWpIIBdrz11uMG\n"
            + "UDalq7GNQYj+M8VXJXB2rpMym93GB+VGjsntjvh52i60sKY12PF5Z4e1dWhrVe9H\n"
            + "zr/mLDBivGdYyAWTEbXRnEWvZO6D+gOebKSSzbHAwpup+8AzSjeUihODckhRAwAO\n"
            + "vIL09E3AiGodBFmAlVrbOmR8fOX3BvdrTKa+Dy7GWCcQzpBX2T/J8fiFebMfBDzQ\n"
            + "iptSO9r+MzirW6lqRJ9bL/XGfOG4jYxuv2X/M/GhEgEzU0vNisTKTziLjM5ecx6N\n"
            + "7dHFX/cwbK36b+Q4u6+bIxfSeLG48IYFjEPkUVjekENw63ZPppza+/TaX/Qj+dDq\n"
            + "LoauUApjxGWwpjNHpwuYsV0=\n"
            + "-----END ENCRYPTED PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    var privateKey = CertUtil.loadBcPrivateKeyResource(pkFile, "P@ssw0rd");
    assertNotNull(privateKey);
    assertTrue(privateKey.isPrivate());
    assertThrows(
        IllegalArgumentException.class, () -> CertUtil.loadBcPrivateKeyResource(pkFile, ""));
  }

  @Test
  void loadJcaPKCS8PrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "pkcs8.key");
    String content =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            + "MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI6T6YzPn438ECAggA\n"
            + "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBw5rDy+syhWjH1bSr1wdpsBIIC\n"
            + "gNpW/bVkikKTmDOhtEUe1ipg+IxNMXJ9yUqWvUFu9OeAZw5AAHR/xfM3efV5aLhl\n"
            + "+D28gFaxSeL6ZipDX3MpM1VTc6/4NJgySce3TP1HKwSUBAL7c4q7KCsHQQ5yX3hh\n"
            + "gAHphmnQEPUEDhbPHRZbfvkyaJrv0jzSymLRaTagTa0a8iJoczcjnmf3NQWNe5YU\n"
            + "En/UPa4T3VMgqLDum7DgfmHPjfOwHYD4rdAZv/J/P6wTdBYyPulvW+lhvWftegu0\n"
            + "Xfj7V6TePbxIviU2IP/Yc5mJ+x4iS0V+JmlY2iYVav8mXBZTVgcPFp3/E3+u97DE\n"
            + "rlz5QPSad5hPG5fKyvDfULomQGQSmi2b54vYe2zsPZ7qudm0Q2d3Wbvg9utI3bPf\n"
            + "z4AGcKvuOWA+GFBU/7YtNF1pLFhalkZp4TMrPknrvO4mjg57CMihty5KspsYHu4d\n"
            + "DH/ielmFAQIhJKgD3ts1+nuNIYWFhSu+gNRw3weNd7p8PpcxDPGWpIIBdrz11uMG\n"
            + "UDalq7GNQYj+M8VXJXB2rpMym93GB+VGjsntjvh52i60sKY12PF5Z4e1dWhrVe9H\n"
            + "zr/mLDBivGdYyAWTEbXRnEWvZO6D+gOebKSSzbHAwpup+8AzSjeUihODckhRAwAO\n"
            + "vIL09E3AiGodBFmAlVrbOmR8fOX3BvdrTKa+Dy7GWCcQzpBX2T/J8fiFebMfBDzQ\n"
            + "iptSO9r+MzirW6lqRJ9bL/XGfOG4jYxuv2X/M/GhEgEzU0vNisTKTziLjM5ecx6N\n"
            + "7dHFX/cwbK36b+Q4u6+bIxfSeLG48IYFjEPkUVjekENw63ZPppza+/TaX/Qj+dDq\n"
            + "LoauUApjxGWwpjNHpwuYsV0=\n"
            + "-----END ENCRYPTED PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    var privateKey = CertUtil.loadJcaPrivateKeyResource(pkFile, "P@ssw0rd");
    assertNotNull(privateKey);
    assertEquals("RSA", privateKey.getAlgorithm());
    assertThrows(
        IllegalArgumentException.class, () -> CertUtil.loadJcaPrivateKeyResource(pkFile, ""));
  }

  @Test
  void loadParseErrorPKCS8PrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "pkcs8.key");
    String content =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            + "MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI6T6YzPn438ECAggA\n"
            + "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBw5rDy+syhWjH1bSr1wdpsBIIC\n"
            + "gNpW/bVkikKTmDOhtEUe1ipg+IxNMXJ9yUqWvUFu9OeAZw5AAHR/xfM3efV5aLhl\n"
            + "+D28gFaxSeL6ZipDX3MpM1VTc6/4NJgySce3TP1HKwSUBAL7c4q7KCsHQQ5yX3hh\n"
            + "gAHphmnQEPUEDhbPHRZbfvkyaJrv0jzSymLRaTagTa0a8iJoczcjnmf3NQWNe5YU\n"
            + "En/UPa4T3VMgqLDum7DgfmHPjfOwHYD4rdAZv/J/P6wTdBYyPulvW+lhvWftegu0\n"
            + "Xfj7V6TePbxIviU2IP/Yc5mJ+x4iS0V+JmlY2iYVav8mXBZTVgcPFp3/E3+u97DE\n"
            + "rlz5QPSad5hPG5fKyvDfULomQGQSmi2b54vYe2zsPZ7qudm0Q2d3Wbvg9utI3bPf\n"
            + "z4AGcKvuOWA+GFBU/7YtNF1pLFhalkZp4TMrPknrvO4mjg57CMihty5KspsYHu4d\n"
            + "DH/ielmFAQIhJKgD3ts1+nuNIYWFhSu+gNRw3weNd7p8PpcxDPGWpIIBdrz11uMG\n"
            + "UDalq7GNQYj+M8VXJXB2rpMym93GB+VGjsntjvh52i60sKY12PF5Z4e1dWhrVe9H\n"
            + "zr/mLDBivGdYyAWTEbXRnEWvZO6D+gOebKSSzbHAwpup+8AzSjeUihODckhRAwAO\n"
            + "vIL09E3AiGodBFmAlVrbOmR8fOX3BvdrTKa+Dy7GWCcQzpBX2T/J8fiFebMfBDzQ\n"
            + "iptSO9r+MzirW6lqRJ9bL/XGfOG4jYxuv2X/M/GhEgEzU0vNisTKTziLjM5ecx6N\n"
            + "7dHFX/cwbK36b+Q4u6+bIxfSeLG48IYFjEPkUVjekENw63ZPppza+/TaX/Qj+dDq\n"
            + "LoauUApjxGWwpjNHpwuYsV0=\n"
            + "-----END ENCRYPTED PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    Security.setProperty(BouncyCastleProvider.PROVIDER_NAME, "1.2.840.113549.1.5.13");
    assertThrows(
        IllegalArgumentException.class, () -> CertUtil.loadBcPrivateKeyResource(pkFile, "Meow!"));
  }

  @Test
  void loadIllegalPKCS8PrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "pkcs8.key");
    String content =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            + "MeowMeow=\n"
            + "-----END ENCRYPTED PRIVATE KEY-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    assertThrows(
        DecoderException.class, () -> CertUtil.loadBcPrivateKeyResource(pkFile, "P@ssw0rd"));
  }

  @Test
  void loadIllegalBcPrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "pkcs8.key");
    String content =
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIEFjCCAv6gAwIBAgIJAKgxIwV0NU0nMA0GCSqGSIb3DQEBCwUAMIGeMQswCQYD\n"
            + "VQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3pob3Ux\n"
            + "FzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMREwDwYDVQQLDAhlcmljc3NvbjEVMBMG\n"
            + "A1UEAwwMZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBlcmlj\n"
            + "c3Nvbi5jb20wIBcNMjEwNzEyMDI0NzM1WhgPMzAyMDExMTIwMjQ3MzVaMIGeMQsw\n"
            + "CQYDVQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3po\n"
            + "b3UxFzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMREwDwYDVQQLDAhlcmljc3NvbjEV\n"
            + "MBMGA1UEAwwMZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBl\n"
            + "cmljc3Nvbi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdT7et\n"
            + "D1Dhv8bfQvnjGMpEtDnl70Wv7rfrFjxRM99rKd0WrPlCtXRuzGYpEBTqdoQHRaMn\n"
            + "FAerHVHrwFBIxgaHNcgb6wv6Xk7Zebgq4loQiQU2UO+L8TWKqB5yRBzi68v90E3z\n"
            + "+8Kigi99XIldtkCcOkYs34np4uHM8jMLGTEQsuw2QupaxzG1a4PqYCOeLEk26+Im\n"
            + "588YUy/jr83hSl6Kfp04VtCxisSIkIlLvENqBptuG2iaDqvNlJm/F8zwkxZDzzMs\n"
            + "4uawa7Og+rPldJIo7gxrP/jo6TogRu0rGLF5iRrHRhGc5RyjMEXrHq5W/JFqSITl\n"
            + "FFLiX6YqZMz+PQV7AgMBAAGjUzBRMB0GA1UdDgQWBBSy9Dp8fvVNWWub8/qabCSo\n"
            + "cfBbkTAfBgNVHSMEGDAWgBSy9Dp8fvVNWWub8/qabCSocfBbkTAPBgNVHRMBAf8E\n"
            + "BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA2sKefy514FOUC5tXVLT+bJ4QxT2Zh\n"
            + "iMGBpMjNt+a1VvzNZb74m+B5St43EjtstGEPMrF0uyokvltnx+R15CL3qTDtYZzj\n"
            + "1Pn13qPbutXNAJX1QzfooOMUjTTADhm9YP1A9c7ERs1YQQ8p0OLZEYmNBlDaMOHX\n"
            + "lStiNZaSYwqSvza2zqM9sNBPSE4LvLrqFFLRNtrP8UlYTKo0bJOhc9ooGJgCeI+w\n"
            + "Qs7BMnTYNCawuJHCbwjJi7O/NEHJbatYOiqzC1ucu45zhid6ICyBQ+yU8RHOGTe4\n"
            + "VLIDeOdztDHQfg7zH3anm73UTM4PmqocecUrYC2okVcIdGRajzwNQolh\n"
            + "-----END CERTIFICATE-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    assertThrows(
        IllegalArgumentException.class,
        () -> CertUtil.loadBcPrivateKeyResource(pkFile, "P@ssw0rd"));
  }

  // openssl genpkey -genparam -algorithm DH -out dhp.pem
  @Test
  void loadUnsupportedBcPrivateKeyResourceTest() throws Exception {
    File pkFile = new File(tempDir, "dhp.pem");
    String content =
        "-----BEGIN DH PARAMETERS-----\n"
            + "MIGHAoGBAOZVzJ4E8766527Mp3FD71xEUYdmFan4tPcSuPO99H7n9xfAm7WytmRQ\n"
            + "gxNn2dz4X58FKLzVMY+x2rLyPOd8SLa3OB7tE+gKFMymswteN//lPbFeLWtyei78\n"
            + "7lGJNnjVDpqJFmo1nldMTDyl5Z+ueZJP5vGGs2ouvem/Cf5N5QRTAgEC\n"
            + "-----END DH PARAMETERS-----\n";
    Files.write(pkFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    var privateKey = CertUtil.loadBcPrivateKeyResource(pkFile, null);
    assertNotNull(privateKey);
    assertTrue(privateKey.isPrivate());
    assertThrows(
        IllegalArgumentException.class,
        () -> CertUtil.loadJcaPrivateKeyResource(pkFile, "P@ssw0rd"));
  }

  @Test
  void loadBcCertificateChainTest() throws Exception {
    File pbFile = new File(tempDir, "ca.crt");
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
  }

  @Test
  void loadJcaCertificateChainTest() throws Exception {
    File pbFile = new File(tempDir, "ca.crt");
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
    var certificates = CertUtil.loadJacCertificateChain(pbFile);
    assertNotNull(certificates);
    assertEquals("X.509", certificates[0].getType());
  }

  @Test
  void loadBcEmptyChainTest() throws Exception {
    File pbFile = new File(tempDir, "ca.crt");
    Files.write(pbFile.toPath(), "".getBytes(StandardCharsets.UTF_8));
    var certificate = CertUtil.loadBcCertificateChain(new BcTlsCrypto(new SecureRandom()), pbFile);
    assertNull(certificate);
  }

  @Test
  void loadJcaEmptyChainTest() throws Exception {
    File pbFile = new File(tempDir, "ca.crt");
    Files.write(pbFile.toPath(), "".getBytes(StandardCharsets.UTF_8));
    var certificates = CertUtil.loadJacCertificateChain(pbFile);
    assertNotNull(certificates);
    assertEquals(0, certificates.length);
  }

  @Test
  void loadBcIllegalChainTest() throws Exception {
    File pbFile = new File(tempDir, "ca.crt");
    String content =
        "-----BEGIN EC PRIVATE KEY-----\n"
            + "MIGkAgEBBDDFa2kKwIrYjDg5pxlNiu9mJdrjrB0P88G+07pf76SwRka5VeptIHOb\n"
            + "Z5/HpKC3oM+gBwYFK4EEACKhZANiAAT00BauqCFjG3QbjfvqqfPM57ARDp0AoiEK\n"
            + "b2yTszVcykxKnuTpbmuagNbdBEFfGmj+tDuC7KvUX+udzWnK1E+X6YmsV101XAgE\n"
            + "LEAXmoxNc6fjNWt9e0ATHi8JKoXi2ZI=\n"
            + "-----END EC PRIVATE KEY-----\n";
    Files.write(pbFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    assertThrows(
        IllegalArgumentException.class,
        () -> CertUtil.loadBcCertificateChain(new BcTlsCrypto(new SecureRandom()), pbFile));
  }

  @Test
  void loadJcaIllegalChainTest() throws Exception {
    File pbFile = new File(tempDir, "ca.crt");
    String content =
        "-----BEGIN EC PRIVATE KEY-----\n"
            + "MIGkAgEBBDDFa2kKwIrYjDg5pxlNiu9mJdrjrB0P88G+07pf76SwRka5VeptIHOb\n"
            + "Z5/HpKC3oM+gBwYFK4EEACKhZANiAAT00BauqCFjG3QbjfvqqfPM57ARDp0AoiEK\n"
            + "b2yTszVcykxKnuTpbmuagNbdBEFfGmj+tDuC7KvUX+udzWnK1E+X6YmsV101XAgE\n"
            + "LEAXmoxNc6fjNWt9e0ATHi8JKoXi2ZI=\n"
            + "-----END EC PRIVATE KEY-----\n";
    Files.write(pbFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    assertThrows(IllegalArgumentException.class, () -> CertUtil.loadJacCertificateChain(pbFile));
  }

  @Test
  void loadCertificateInOneFileTest() throws Exception {
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
            + "-----END CERTIFICATE-----\n"
            + "-----BEGIN CERTIFICATE-----\n"
            + "MIIDKTCCApKgAwIBAgIJAJg8poFPQHXNMA0GCSqGSIb3DQEBCwUAMIGrMQswCQYD\n"
            + "VQQGEwJTRTETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UEBwwJR3Vhbmdkb25n\n"
            + "MREwDwYDVQQKDAhFcmljc3NvbjEVMBMGA1UECwwMRXJpY3Nzb24gQURQMSQwIgYD\n"
            + "VQQDDBtpcGZpeGNvbGxlY3Rvci5lcmljc3Nvbi5jb20xIzAhBgkqhkiG9w0BCQEW\n"
            + "FGVoY2F5ZW5AZXJpY3Nzb24uY29tMB4XDTIxMDcyMjA2NDUxNVoXDTIyMDcyMjA2\n"
            + "NDUxNVowgasxCzAJBgNVBAYTAlNFMRMwEQYDVQQIDApTb21lLVN0YXRlMRIwEAYD\n"
            + "VQQHDAlHdWFuZ2RvbmcxETAPBgNVBAoMCEVyaWNzc29uMRUwEwYDVQQLDAxFcmlj\n"
            + "c3NvbiBBRFAxJDAiBgNVBAMMG2lwZml4Y29sbGVjdG9yLmVyaWNzc29uLmNvbTEj\n"
            + "MCEGCSqGSIb3DQEJARYUZWhjYXllbkBlcmljc3Nvbi5jb20wgZ8wDQYJKoZIhvcN\n"
            + "AQEBBQADgY0AMIGJAoGBAL9jr9EYK7ZPSB0h8trcZy1n8oXu2E2DYyXA63Xhi3sS\n"
            + "hT9TGZLfJ29nPmxvWaCh0Ht/vjV6pxbF2ERV1Gu2pQ5bYHCm2lptHSu8L+vRqrNb\n"
            + "UG6/0De88XLmInSrxW+tJGDgV/V2F2Lyg/zf+f2dyyw5znLsgX9J83wL6FeLlb4D\n"
            + "AgMBAAGjUzBRMB0GA1UdDgQWBBTF4q84xFWsJvmW+vNuCQ/dmDrj2jAfBgNVHSME\n"
            + "GDAWgBTF4q84xFWsJvmW+vNuCQ/dmDrj2jAPBgNVHRMBAf8EBTADAQH/MA0GCSqG\n"
            + "SIb3DQEBCwUAA4GBABnJ1GDwd69Jkb9k0dbuc4f2pmZfipftpKrN1jDvlUOTGJMF\n"
            + "Y6pO0NfMQZEigZ7akZZ7PZq2Td9U3sm+WPFZfNFu5xuqxb3iMC3PxNpRQPjoAT9e\n"
            + "R0chKtiqBtMfxkBEXmO5R4NhIpVM+JsQx5lyoJwTFXMu1UZvHBs4zTJwVUnN\n"
            + "-----END CERTIFICATE-----\n";
    File pbFile = new File(tempDir, "ca.crt");
    Files.write(pbFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    var certificate = CertUtil.loadBcCertificateChain(new BcTlsCrypto(new SecureRandom()), pbFile);
    assertNotNull(certificate);
    assertEquals(CertificateType.X509, certificate.getCertificateType());
    assertEquals(2, certificate.getCertificateList().length);
  }

  @Test
  void loadCertificateMultiChainTest() throws Exception {
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
    File pbFile1 = new File(tempDir, "ca1.crt");
    Files.write(pbFile1.toPath(), content.getBytes(StandardCharsets.UTF_8));
    File pbFile2 = new File(tempDir, "ca2.crt");
    // write an empty file
    Files.write(pbFile2.toPath(), "".getBytes(StandardCharsets.UTF_8));
    File pbFile3 = new File(tempDir, "ca3.crt");
    content =
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIGMDCCBBigAwIBAgIJAN95q8b6AFRkMA0GCSqGSIb3DQEBCwUAMIGsMQswCQYD\n"
            + "VQQGEwJTRTETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UEBwwJR3Vhbmdkb25n\n"
            + "MREwDwYDVQQKDAhFcmljc3NvbjEVMBMGA1UECwwMRXJpY3Nzb24gQURQMSUwIwYD\n"
            + "VQQDDBxpcGZpeGNvbGxlY3Rpb24uZXJpY3Nzb24uY29tMSMwIQYJKoZIhvcNAQkB\n"
            + "FhRlaGNheWVuQGVyaWNzc29uLmNvbTAeFw0yMTA3MjAwODE1NDRaFw0yMjA3MjAw\n"
            + "ODE1NDRaMIGsMQswCQYDVQQGEwJTRTETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAG\n"
            + "A1UEBwwJR3Vhbmdkb25nMREwDwYDVQQKDAhFcmljc3NvbjEVMBMGA1UECwwMRXJp\n"
            + "Y3Nzb24gQURQMSUwIwYDVQQDDBxpcGZpeGNvbGxlY3Rpb24uZXJpY3Nzb24uY29t\n"
            + "MSMwIQYJKoZIhvcNAQkBFhRlaGNheWVuQGVyaWNzc29uLmNvbTCCAiIwDQYJKoZI\n"
            + "hvcNAQEBBQADggIPADCCAgoCggIBAMnKFsTBtNpDeCG5BEXbav1uRTM2hAw5aBb7\n"
            + "6wpc+ctdlOxJPZ1NnD4n9ERQA+jc+L46W2DPf+XDV/lGMwS+lQjZ4PdjNPsjoax+\n"
            + "SxeqM4OrOrVIEcuFVH1UVwXgabN1PQF+1b6V3aUQfJV6bY98bA1fgaqDh6JnSMno\n"
            + "ek6YomCHED70ZyRoAKxAOkHQtVaxmq1j//ny6SrFIscsQ2x3pveunaLdiHf8hegs\n"
            + "p26tUeeAs/8NNfCAE0wnQijumFgZrFQxNa6mIIlruAlMG1xxXVKGT1dkHlXrG294\n"
            + "bAHjxeyAZOMxoUMZ1JQ0a4b+lXztdis2q8qfaP21VJ2tWf01qeSen0QNcnlcLLQ8\n"
            + "NaOHzbBR+1ZkGEqVDq9BEdPyuQ2jPoCXayLwKs8MLeuiosEKXMJJiQ1Yn3PsoGD9\n"
            + "Q9fIShNZeL59AKcNqcxL3x4/TC4E/ePnsGfbtcFqy6UukY+Y77gk2nk8SOgo2Kfu\n"
            + "VAMtWjeCacr+PzsAsKNgoVB8J957ENUV25bvlkXfD9khwzeklo0q9FMu/aD2Z1sH\n"
            + "9bQL7nj3IN2xJtYJ88nMuK1wY0xaOafLgaTPMp90v6QJpr3PGHwv97S838Yt6Rgy\n"
            + "6Sqzm1S4nlbQESjOxhbq6r/KIsAAOtV+iRugmGnVE4p9IHMJYxosC2dT3XYOkr3x\n"
            + "ey80L4N9AgMBAAGjUzBRMB0GA1UdDgQWBBRebJz4nwcDkbjUrQGUm18OpcovAzAf\n"
            + "BgNVHSMEGDAWgBRebJz4nwcDkbjUrQGUm18OpcovAzAPBgNVHRMBAf8EBTADAQH/\n"
            + "MA0GCSqGSIb3DQEBCwUAA4ICAQBDAenC4+ASbRwywPSFpaXLfiY2terfQfs5FSiJ\n"
            + "u+s/jo/ghra7HOtkTuvtPN/pCPSdDTzWrrKNsGP5ZdF9qlQjK6zQaIIkISn1ScRh\n"
            + "E/1rvevhY09N5sskdgUSuljbJW3iqqhuqt0TjCa318t2vxUEcSHAL+FvtzVDrgx0\n"
            + "NTVOwVb+5d86/9WF0MF2XIMI/haO7Vgh25VvZCp63mpF72yx5jzbJeXJN+ReFQfV\n"
            + "PuaOUDU3ANUHpwZH0rpt75Z2bZ1d1gifOI4DjXEFgyPA17ZghNo/uVPsW0Y0mQq5\n"
            + "FwEPL4GETcR2brZFpOxzQUA82PZl9KRebsYVYTTYXWjq0OMx0EfzjL5sXxJaADdw\n"
            + "RN/iQHoPKJHY92/R3w1SH+CAOkDFSfX8/n9kHG3ZvM2YzbVjgS/pBclbGZMUc9Wt\n"
            + "86PkL2kTRwlKVGQGt008yuY5ktLsMRyD4OjUyENLd3ZjT/JIcOMh6/njZ742UFRW\n"
            + "RDb3E8QkrdsEJvLIaJBGzzl9GlW2dvrJpVL676FhYkCZcP8fdY3UcOcNMWwM+tpk\n"
            + "xLWdwgJ5CeMJmHclhQsU1XEZKWZqi8HrqLYZl/3qwqpvXSrF40a9R0mOCAghka3H\n"
            + "YTHACFepm8RvHkDBHNTyfg7atvdBr0ttsRrdoJdJsYJGeOjCtcZ35OmbfIj5lgEG\n"
            + "PmkpUg==\n"
            + "-----END CERTIFICATE-----\n";
    Files.write(pbFile3.toPath(), content.getBytes(StandardCharsets.UTF_8));

    var certificate =
        CertUtil.loadBcCertificateChain(
            new BcTlsCrypto(new SecureRandom()), pbFile1, pbFile2, pbFile3);
    assertNotNull(certificate);
    assertEquals(CertificateType.X509, certificate.getCertificateType());
    assertEquals(2, certificate.getCertificateList().length);
  }
}
