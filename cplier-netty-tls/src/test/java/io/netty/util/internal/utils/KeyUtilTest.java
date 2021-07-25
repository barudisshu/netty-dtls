package io.netty.util.internal.utils;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class KeyUtilTest {

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void getKeyFactoryTest() throws Exception {
    assertThrows(InvalidKeySpecException.class, () -> KeyUtil.getKeyFactory("AES"));
    var keyFactory = KeyUtil.getKeyFactory("RSA");
    assertNotNull(keyFactory);
  }

  @Test
  void generateRSAPublicKeyTest() throws Exception {
    var pkInfo = createSubjectPublicKeyInfo("RSA", "SHA256withRSA");
    PublicKey publicKey = KeyUtil.generatePublicKey(pkInfo);
    assertNotNull(publicKey);
    assertEquals("RSA", publicKey.getAlgorithm());
  }

  @Test
  void generateDSAPublicKeyTest() throws Exception {
    var pkInfo = createSubjectPublicKeyInfo("DSA", "SHA256withDSA");
    PublicKey publicKey = KeyUtil.generatePublicKey(pkInfo);
    assertNotNull(publicKey);
    assertEquals("DSA", publicKey.getAlgorithm());
  }

  @Test
  void generateECPublicKeyTest() throws Exception {
    var pkInfo = createSubjectPublicKeyInfo("EC", "SHA256withECDSA");
    PublicKey publicKey = KeyUtil.generatePublicKey(pkInfo);
    assertNotNull(publicKey);
    assertEquals("EC", publicKey.getAlgorithm());
  }

  @Test
  void generateED25519PublicKeyTest() throws Exception {
    var pkInfo = createSubjectPublicKeyInfo("Ed25519", "Ed25519");
    assertThrows(InvalidKeySpecException.class, () -> KeyUtil.generatePublicKey(pkInfo));
  }

  @Test
  void generateDSAPrivateKeyTest() throws InvalidKeyException {
    BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
    byte[] seed = Hex.decode("ED8BEE8D1CB89229D2903CBF0E51EE7377F48698");
    DSAParametersGenerator pGen = new DSAParametersGenerator();
    pGen.init(new DSAParameterGenerationParameters(1024, 160, 80, new SecureRandom(seed)));
    DSAParameters dsaParameters = pGen.generateParameters();
    DSAPrivateKeyParameters dsaPrivateKeyParameters =
        new DSAPrivateKeyParameters(rootSerialNum, dsaParameters);
    var privateKey = KeyUtil.generatePrivateKey(dsaPrivateKeyParameters);
    assertNotNull(privateKey);
    assertEquals("DSA", privateKey.getAlgorithm());
  }

  @Test
  void generateECPrivateKeyTest() throws InvalidKeyException {
    BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");
    ECCurve.Fp curve =
        new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
            n,
            ECConstants.ONE);
    ECDomainParameters params =
        new ECDomainParameters(
            curve,
            curve.decodePoint(
                Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
            n);
    ECPrivateKeyParameters priKey =
        new ECPrivateKeyParameters(
            new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
            params);
    var privateKey = KeyUtil.generatePrivateKey(priKey);
    assertNotNull(privateKey);
    assertEquals("EC", privateKey.getAlgorithm());
  }

  @Test
  void generateRSAPrivateKeyTest() throws InvalidKeyException {
    BigInteger mod =
        new BigInteger(
            "b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5",
            16);
    BigInteger pubExp = new BigInteger("11", 16);
    BigInteger privExp =
        new BigInteger(
            "92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619",
            16);
    BigInteger p =
        new BigInteger(
            "f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03",
            16);
    BigInteger q =
        new BigInteger(
            "b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947",
            16);
    BigInteger pExp =
        new BigInteger(
            "1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5",
            16);
    BigInteger qExp =
        new BigInteger(
            "6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded",
            16);
    BigInteger crtCoef =
        new BigInteger(
            "dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339",
            16);
    RSAKeyParameters priKey =
        new RSAPrivateCrtKeyParameters(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);
    var privateKey = KeyUtil.generatePrivateKey(priKey);
    assertNotNull(privateKey);
    assertEquals("RSA", privateKey.getAlgorithm());
  }

  @Test
  void generateHDPrivateKeyTest() {
    BigInteger g512 =
        new BigInteger(
            "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc",
            16);
    BigInteger p512 =
        new BigInteger(
            "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b",
            16);
    DHParameters dhParams = new DHParameters(p512, g512);
    DHKeyGenerationParameters params = new DHKeyGenerationParameters(new SecureRandom(), dhParams);
    DHKeyPairGenerator kpGen = new DHKeyPairGenerator();
    kpGen.init(params);
    AsymmetricCipherKeyPair pair = kpGen.generateKeyPair();
    DHPrivateKeyParameters priKey = (DHPrivateKeyParameters) pair.getPrivate();
    // although the AsymmetricKeyParameter is a DH private key but we does not support it.
    assertThrows(InvalidKeyException.class, () -> KeyUtil.generatePrivateKey(priKey));
  }

  @Test
  void generateWrongPrivateKeyTest() {
    BigInteger mod =
        new BigInteger(
            "b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5",
            16);
    BigInteger pubExp = new BigInteger("11", 16);
    RSAKeyParameters priKey = new RSAKeyParameters(false, mod, pubExp);
    assertThrows(InvalidKeyException.class, () -> KeyUtil.generatePrivateKey(priKey));
  }

  @Test
  void generateDSAParamPublicKeyTest() throws InvalidKeyException {
    DSAParameters dsaParams =
        new DSAParameters(
            new BigInteger(
                "F56C2A7D366E3EBDEAA1891FD2A0D099"
                    + "436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91"
                    + "D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C"
                    + "69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2"
                    + "5909132627F51A0C866877E672E555342BDF9355347DBD43"
                    + "B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431"
                    + "31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A"
                    + "EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD"
                    + "F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF"
                    + "1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D"
                    + "531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75",
                16),
            new BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16),
            new BigInteger(
                "8DC6CC814CAE4A1C05A3E186A6FE27EA"
                    + "BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1"
                    + "29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB"
                    + "6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2"
                    + "513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869"
                    + "7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0"
                    + "A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403"
                    + "45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8"
                    + "FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E"
                    + "428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC"
                    + "EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279",
                16));
    BigInteger y =
        new BigInteger(
            "2828003D7C747199143C370FDD07A286"
                + "1524514ACC57F63F80C38C2087C6B795B62DE1C224BF8D1D"
                + "1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EA"
                + "CBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500"
                + "C611957DBF5ED35490714A42811FDCDEB19AF2AB30BEADFF"
                + "2907931CEE7F3B55532CFFAEB371F84F01347630EB227A41"
                + "9B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF"
                + "41566E26FAEE475137EC781A0DC088A26C8804A98C23140E"
                + "7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1D"
                + "C97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AE"
                + "A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B",
            16);
    DSAPublicKeyParameters pub = new DSAPublicKeyParameters(y, dsaParams);
    PublicKey publicKey = KeyUtil.generatePublicKey(pub);
    assertNotNull(publicKey);
    assertEquals("DSA", publicKey.getAlgorithm());
  }

  @Test
  void generateECParamPublicKeyTest() throws InvalidKeyException {
    BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");
    ECCurve.Fp curve =
        new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
            n,
            ECConstants.ONE);
    ECDomainParameters params =
        new ECDomainParameters(
            curve,
            curve.decodePoint(
                Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
            n);

    ECPublicKeyParameters pub =
        new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")),
            params);
    PublicKey publicKey = KeyUtil.generatePublicKey(pub);
    assertNotNull(publicKey);
    assertEquals("EC", publicKey.getAlgorithm());
  }

  @Test
  void generateRSAParamPublicKeyTest() throws InvalidKeyException {
    BigInteger mod =
        new BigInteger(
            "b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5",
            16);
    BigInteger pubExp = new BigInteger("11", 16);
    RSAKeyParameters priKey = new RSAKeyParameters(false, mod, pubExp);
    PublicKey publicKey = KeyUtil.generatePublicKey(priKey);
    assertNotNull(publicKey);
    assertEquals("RSA", publicKey.getAlgorithm());
  }

  @Test
  void generateWrongParamPublicKeyTest() {
    BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
    byte[] seed = Hex.decode("ED8BEE8D1CB89229D2903CBF0E51EE7377F48698");
    DSAParametersGenerator pGen = new DSAParametersGenerator();
    pGen.init(new DSAParameterGenerationParameters(1024, 160, 80, new SecureRandom(seed)));
    DSAParameters dsaParameters = pGen.generateParameters();
    DSAPrivateKeyParameters dsaPrivateKeyParameters =
        new DSAPrivateKeyParameters(rootSerialNum, dsaParameters);
    assertThrows(
        InvalidKeyException.class, () -> KeyUtil.generatePublicKey(dsaPrivateKeyParameters));
  }

  @Test
  void generateUnsupportedParamPublicKeyTest() {
    BigInteger g512 =
        new BigInteger(
            "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc",
            16);
    BigInteger p512 =
        new BigInteger(
            "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b",
            16);
    DHParameters dhParams = new DHParameters(p512, g512);
    DHKeyGenerationParameters params = new DHKeyGenerationParameters(new SecureRandom(), dhParams);
    DHKeyPairGenerator kpGen = new DHKeyPairGenerator();
    kpGen.init(params);
    AsymmetricCipherKeyPair pair = kpGen.generateKeyPair();
    DHPublicKeyParameters pub = (DHPublicKeyParameters) pair.getPublic();
    // although the AsymmetricKeyParameter is a DH private key but we does not support it.
    assertThrows(InvalidKeyException.class, () -> KeyUtil.generatePublicKey(pub));
  }

  @Test
  void generateRSAPrivateKeyParameterTest() throws NoSuchAlgorithmException, InvalidKeyException {
    var privateKey = createPrivateKey("RSA");
    var asymmetricKeyParameter = KeyUtil.generatePrivateKeyParameter(privateKey);
    assertNotNull(asymmetricKeyParameter);
    assertTrue(asymmetricKeyParameter.isPrivate());
  }

  @Test
  void generatePKCS8PrivateKeyParameterTest()
      throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
    byte[] encPriv =
        Base64.decode(
            " MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1TpIe8iB2h4qb0K54qhH6LXcjhd"
                + "kDOo9X5tp2dR2tOULOJM19sZ0RVJE+St01xDNh6CPrwrWAdhPvnl020oCqckfqTqhB8fTzcxPR5htOeLWx/fM05j42zjMjKbfMwEPlVDqn"
                + "N9KT1JnKxuiGF4SQwsuDoJirjHWzGexLV9rtfaa5spebGhqbm3STO1c8jS/sTqJhZh+Igi8SKvrjbXN9+TSDLOd8s0/UdZKm1w6A01tEXI"
                + "a8+HxkXLCug0BPB9AVMRnql/cXDt4yUw3R4OO9WJv2/aIQvYNINnE4dib2Q8XYRMm5FGgSrolbYApKzfJ5N/y5sRme56ohRbqUoUR3AgMB"
                + "AAECggEAFV6j6WLXgbD7HN9tWQqOoOKv+q9hgzhpQc6TbEfkjhDEN4Dt+YUwQqUpk2KGjTpJZh5S8YxbET+ZnPIZAYexI6XhpRPNUCyBFx"
                + "q2uNQ63rZqkAajHlaO+a23KEtX/xmgRwz09tWlC8iQse5c5MUr2lYjX6nTpNCi5M/G4qCBzOEByjxkKCXbgaTKsgLb7ax2CoC3BUbWjQnb"
                + "Q2V9tRImBX92b1NF0ER0Xovy7VH0rwrQnTEkD8U6OrRs+UAX+zCzkV69BJPou47s4jSdDksy5vhteVdx+HnucEeLgpJoqixiDWofZvX7+N"
                + "AsGs+e74bV/vQinuY6a1ILEH3g1+rhGQKBgQD1J7sUdmbXelGUys5rERdYP9xTNuyqV38DrgPDyE8pgpwrvM5gn1cRb8Wop6xOp/vVME8F"
                + "u9PE65+T5nRb8zEvypi+4mGsjksI7ZsQ4VqV7G1GfTT8QKjr+gEk7t+jN2ymL6lp2x+bbSHQniPP51FDl72RsKY0Pk4Iy9aMKbxXHwKBgQ"
                + "C9U8mqMveT8e+ztiVwUdM2AvQSv+WNyVD5q78db5mrxur20b8UU7cyDFJoH6Y72GT/sKuL4LSAD8ZrUg5rnZWtXP63WnAlRJaMI0d7McV7"
                + "OwsaByJVlI/Yq3OpC8x1+Pf1jy6HJzxFVmMMllYi63CzqPwIAgnGdHP4C/p/CmEfqQKBgG6ip4LsjCziPr7vZ4haBjcFWuETAGs/YUq/1W"
                + "MdmtwY3XG/m0NvpVNxJbqfMNuuY7AqRP9JbKCJ1VJhxlFYxvHSdGxwrbO545L75+cOTFssf4Q4LRlJ9PHJuYp5YuO9t4KoL8Rd5z21WnVT"
                + "aMYClmHysNJ27grVs1G06/YFP8HxAoGAKvFjT5CJ6Wu58+g/q69Tme+njs0p8zQTgt361mFm2LiguOUwUxr99YMn+egb230kw34+GtcX+e"
                + "gaGGOfU7eFqLHsMIh54WoiP50M7JuIcIAe74NovUKaMgoJjPFZKfUTwQX+BrfWit+iTcuXtAn1ITsWF3bm4rWtTDjjU4d2KikCgYEA7Zwj"
                + "/hGL7pmbDjfBK0aG+06JPQ1LHYVXHOUxco9eB1sgJXoxBjqoJPU0j7NCrn6i3tiDtLPYNAO9ehaRLucFk8FjthrewHmZY+x+nmzkEbMbi1"
                + "kDTIvY4pw5jn9k5CEBAe2MSymjzfPTWV2YhuG1Lu5ibSQ+LMMbUppniD9N2pA=");
    KeyFactory keyFact = KeyFactory.getInstance("RSA");
    PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));
    PrivateKey privateKey =
        keyFact.generatePrivate(
            new RSAPrivateKeySpec(
                ((RSAPrivateKey) priv).getModulus(), ((RSAPrivateKey) priv).getPrivateExponent()));
    var asymmetricKeyParameter = KeyUtil.generatePrivateKeyParameter(privateKey);
    assertNotNull(asymmetricKeyParameter);
    assertTrue(asymmetricKeyParameter.isPrivate());
  }

  @Test
  void generateECPrivateKeyParameterTest() throws NoSuchAlgorithmException, InvalidKeyException {
    var privateKey = createPrivateKey("EC");
    var asymmetricKeyParameter = KeyUtil.generatePrivateKeyParameter(privateKey);
    assertNotNull(asymmetricKeyParameter);
    assertTrue(asymmetricKeyParameter.isPrivate());
  }

  @Test
  void generateDSAPrivateKeyParameterTest() throws InvalidKeyException, NoSuchAlgorithmException {
    var privateKey = createPrivateKey("DSA");
    var asymmetricKeyParameter = KeyUtil.generatePrivateKeyParameter(privateKey);
    assertNotNull(asymmetricKeyParameter);
    assertTrue(asymmetricKeyParameter.isPrivate());
  }

  @Test
  void generateUnsupportedPrivateKeyParameterTest() throws NoSuchAlgorithmException {
    var privateKey = createPrivateKey("Ed25519");
    assertThrows(InvalidKeyException.class, () -> KeyUtil.generatePrivateKeyParameter(privateKey));
  }

  @Test
  void generateRSAPublicKeyParameterTest() throws InvalidKeyException, NoSuchAlgorithmException {
    var publicKey = createPublicKey("RSA");
    var asymmetricKeyParameter = KeyUtil.generatePublicKeyParameter(publicKey);
    assertNotNull(asymmetricKeyParameter);
    assertFalse(asymmetricKeyParameter.isPrivate());
  }

  @Test
  void generateECPublicKeyParameterTest() throws NoSuchAlgorithmException, InvalidKeyException {
    var publicKey = createPublicKey("EC");
    var asymmetricKeyParameter = KeyUtil.generatePublicKeyParameter(publicKey);
    assertNotNull(asymmetricKeyParameter);
    assertFalse(asymmetricKeyParameter.isPrivate());
  }

  @Test
  void generateDSAPublicKeyParameterTest() throws NoSuchAlgorithmException, InvalidKeyException {
    var publicKey = createPublicKey("DSA");
    var asymmetricKeyParameter = KeyUtil.generatePublicKeyParameter(publicKey);
    assertNotNull(asymmetricKeyParameter);
    assertFalse(asymmetricKeyParameter.isPrivate());
  }

  @Test
  void generateUnsupportedPublicKeyParameterTest() throws NoSuchAlgorithmException {
    var publicKey = createPublicKey("DH");
    assertThrows(InvalidKeyException.class, () -> KeyUtil.generatePublicKeyParameter(publicKey));
  }

  private PrivateKey createPrivateKey(String algorithm) throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
    KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
    return rootKeyPair.getPrivate();
  }

  private PublicKey createPublicKey(String algorithm) throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
    KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
    return rootKeyPair.getPublic();
  }

  private SubjectPublicKeyInfo createSubjectPublicKeyInfo(
      String algorithm, String signatureAlgorithm)
      throws OperatorCreationException, NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
    KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
    X500Name rootCertIssuer = new X500Name("CN=root-cert");
    PKCS10CertificationRequestBuilder p10Builder =
        new JcaPKCS10CertificationRequestBuilder(rootCertIssuer, rootKeyPair.getPublic());
    JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
    ContentSigner csrContentSigner = csrBuilder.build(rootKeyPair.getPrivate());
    PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);
    return csr.getSubjectPublicKeyInfo();
  }
}
