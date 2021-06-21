package io.netty.util.internal.cert.bctls.domain;

import io.netty.util.internal.cert.bctls.api.KeyPairInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Path;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(MockitoExtension.class)
class KeyPairManagerTest {

  @Test
  void testCreateKey(@TempDir Path tempFolder) {

    KeyPairManager manager =
        new KeyPairManager(tempFolder, new BouncyCastleProvider(), new SecureRandom());

    assertNotNull(manager.newKeyPair("test"));

    KeyPairInfo info = manager.getKeyPairInfo("test");

    assertEquals("test", info.getName());
    assertEquals("ECDSA", info.getAlgorithm());
    assertNotNull(info.getPublicKey());
  }
}
