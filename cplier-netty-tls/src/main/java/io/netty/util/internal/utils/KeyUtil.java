package io.netty.util.internal.utils;

import io.netty.util.internal.adapter.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Only support RSA/DSA/ECDSA
 *
 * @author ehcayen
 * @see CertUtil
 */
public final class KeyUtil {

  private static final Map<String, KeyFactory> KEY_FACTORIES = new HashMap<>();

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private KeyUtil() {}

  /**
   * Only support symmetric cryptography, or else throw exception.
   *
   * @param algorithm crypt alg
   * @return {@link KeyFactory}
   * @throws InvalidKeySpecException invalid key specification
   */
  public static KeyFactory getKeyFactory(final String algorithm) throws InvalidKeySpecException {
    synchronized (KEY_FACTORIES) {
      KeyFactory kf = KEY_FACTORIES.get(algorithm);
      if (kf != null) {
        return kf;
      }

      try {
        kf = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
      } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
        throw new InvalidKeySpecException(
            "could not find KeyFactory for " + algorithm + ": " + ex.getMessage());
      }
      KEY_FACTORIES.put(algorithm, kf);
      return kf;
    }
  }

  public static PublicKey generatePublicKey(final SubjectPublicKeyInfo pkInfo)
      throws InvalidKeySpecException, IOException {
    X509EncodedKeySpec keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
    ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();
    String algorithm;
    if (PKCSObjectIdentifiers.rsaEncryption.equals(aid)) {
      algorithm = "RSA";
    } else if (X9ObjectIdentifiers.id_dsa.equals(aid)) {
      algorithm = "DSA";
    } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(aid)) {
      algorithm = "EC";
    } else {
      throw new InvalidKeySpecException("unsupported key algorithm: " + aid);
    }

    KeyFactory kf = getKeyFactory(algorithm);
    synchronized (KEY_FACTORIES) {
      return kf.generatePublic(keyspec);
    }
  }

  /**
   * To the limit that Only support RSA/DSA/ECDSA algorithm, pkcs8 is not recommended!!
   *
   * @param asymmetricKeyParameter {@link AsymmetricKeyParameter}
   * @return {@link PrivateKey}
   * @throws InvalidKeyException key invalid
   * @see CertUtil#loadBcPrivateKeyResource(File, String)
   */
  public static PrivateKey generatePrivateKey(final AsymmetricKeyParameter asymmetricKeyParameter)
      throws InvalidKeyException {
    if (!asymmetricKeyParameter.isPrivate()) {
      throw new InvalidKeyException(
          "AsymmetricKeyParameter is not a private key " + asymmetricKeyParameter);
    }
    final PrivateKey key;
    if (asymmetricKeyParameter instanceof DSAPrivateKeyParameters) {
      key = new WrappedDSAPrivateKey((DSAPrivateKeyParameters) asymmetricKeyParameter);
    } else if (asymmetricKeyParameter instanceof ECPrivateKeyParameters) {
      key = new WrappedECPrivateKey((ECPrivateKeyParameters) asymmetricKeyParameter);
    } else if (asymmetricKeyParameter instanceof RSAPrivateCrtKeyParameters) {
      key = new WrappedRSAPrivateCrtKey((RSAPrivateCrtKeyParameters) asymmetricKeyParameter);
    } else {
      throw new InvalidKeyException("Unsupported private key " + asymmetricKeyParameter);
    }
    return key;
  }

  /**
   * Generate public from AsymmetricKeyParameter
   *
   * @param asymmetricKeyParameter {@link AsymmetricKeyParameter}
   * @return {@link PublicKey}
   * @throws InvalidKeyException key invalid
   */
  public static PublicKey generatePublicKey(final AsymmetricKeyParameter asymmetricKeyParameter)
      throws InvalidKeyException {
    if (asymmetricKeyParameter.isPrivate()) {
      throw new InvalidKeyException(
          "AsymmetricKeyParameter is not a public key " + asymmetricKeyParameter);
    }
    final PublicKey key;
    if (asymmetricKeyParameter instanceof DSAPublicKeyParameters) {
      key = new WrappedDSAPublicKey((DSAPublicKeyParameters) asymmetricKeyParameter);
    } else if (asymmetricKeyParameter instanceof ECPublicKeyParameters) {
      key = new WrappedECPublicKey((ECPublicKeyParameters) asymmetricKeyParameter);
    } else if (asymmetricKeyParameter instanceof RSAKeyParameters) {
      key = new WrappedRSAPublicKey((RSAKeyParameters) asymmetricKeyParameter);
    } else {
      throw new InvalidKeyException("Unsupported public key " + asymmetricKeyParameter);
    }
    return key;
  }

  public static AsymmetricKeyParameter generatePrivateKeyParameter(final PrivateKey key)
      throws InvalidKeyException {
    if (key instanceof RSAPrivateCrtKey) {
      RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
      return new RSAPrivateCrtKeyParameters(
          rsaKey.getModulus(),
          rsaKey.getPublicExponent(),
          rsaKey.getPrivateExponent(),
          rsaKey.getPrimeP(),
          rsaKey.getPrimeQ(),
          rsaKey.getPrimeExponentP(),
          rsaKey.getPrimeExponentQ(),
          rsaKey.getCrtCoefficient());
    } else if (key instanceof RSAPrivateKey) {
      RSAPrivateKey rsaKey = (RSAPrivateKey) key;
      return new RSAKeyParameters(true, rsaKey.getModulus(), rsaKey.getPrivateExponent());
    } else if (key instanceof ECPrivateKey) {
      return ECUtil.generatePrivateKeyParameter(key);
    } else if (key instanceof DSAPrivateKey) {
      return DSAUtil.generatePrivateKeyParameter(key);
    } else {
      throw new InvalidKeyException("unknown key " + key.getClass().getName());
    }
  }

  public static AsymmetricKeyParameter generatePublicKeyParameter(final PublicKey key)
      throws InvalidKeyException {
    if (key instanceof RSAPublicKey) {
      RSAPublicKey rsaKey = (RSAPublicKey) key;
      return new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent());
    } else if (key instanceof ECPublicKey) {
      return ECUtil.generatePublicKeyParameter(key);
    } else if (key instanceof DSAPublicKey) {
      return DSAUtil.generatePublicKeyParameter(key);
    } else {
      throw new InvalidKeyException("unknown key " + key.getClass().getName());
    }
  }
}
