package io.netty.util.internal.cert.bctls.domain;

import io.netty.util.internal.cert.bctls.api.KeyPairInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.netty.util.internal.cert.bctls.domain.KeyPairManager.Algorithm.EC;
import static java.nio.file.StandardOpenOption.CREATE_NEW;

public class KeyPairManager {

  public enum Algorithm {
    EC,
    RSA
  }

  private final Path keysFolder;
  private final BouncyCastleProvider provider;
  private final SecureRandom secureRandom;

  public KeyPairManager(Path keysFolder, BouncyCastleProvider provider, SecureRandom secureRandom) {
    this.keysFolder = keysFolder;
    this.provider = provider;
    this.secureRandom = secureRandom;
  }

  private KeyPair generateKeyPair(Algorithm algorithm, int keySize) {
    KeyPairGenerator generator;

    switch (algorithm) {
      case EC:
        generator = new EC();
        break;
      case RSA:
        generator = new KeyPairGeneratorSpi();
        break;
      default:
        throw new IllegalArgumentException("Unknown certificate algorithm type " + algorithm);
    }

    generator.initialize(keySize, secureRandom);

    return generator.generateKeyPair();
  }

  public KeyPair newKeyPair(String name) {
    return newKeyPair(name, EC, 384);
  }

  public KeyPair newKeyPair(String name, Algorithm algorithm, int keyLength) {

    Path keyFile = keysFolder.resolve(name);
    try (var pw = new JcaPEMWriter(Files.newBufferedWriter(keyFile, CREATE_NEW))) {
      var keyPair = generateKeyPair(algorithm, keyLength);
      pw.writeObject(keyPair.getPrivate());
      return keyPair;
    } catch (FileAlreadyExistsException fae) {
      throw new IllegalArgumentException("There is already a key pair with name " + name);
    } catch (Exception e) {
      var re = new RuntimeException(e);
      try {
        Files.delete(keyFile);
      } catch (IOException e1) {
        re.addSuppressed(e1);
      }
      throw re;
    }
  }

  public KeyPair getKeyPair(String name) {
    Path keyFile = keysFolder.resolve(name);
    try (var parser = new PEMParser(Files.newBufferedReader(keyFile))) {
      PEMKeyPair keyPair = (PEMKeyPair) parser.readObject();
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(provider);
      return new KeyPair(
          converter.getPublicKey(keyPair.getPublicKeyInfo()),
          converter.getPrivateKey(keyPair.getPrivateKeyInfo()));

    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public Map<String, KeyPairInfo> listKeyPairs() {

    try (Stream<Path> s = Files.list(keysFolder)) {
      return s.map(p -> p.getFileName().toString())
          .collect(Collectors.toMap(Function.identity(), this::getKeyPairInfo));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public KeyPairInfo getKeyPairInfo(String name) {
    var pair = getKeyPair(name);
    var kpi = new KeyPairInfo();
    kpi.setName(name);
    kpi.setAlgorithm(pair.getPublic().getAlgorithm());
    kpi.setPublicKey(pair.getPublic().getEncoded());
    return kpi;
  }
}
