/*-
 * #%L
 * io.netty.util.internal.cert
 * %%
 * Copyright (C) 2018 - 2019 Paremus Ltd
 * %%
 * Licensed under the Fair Source License, Version 0.9 (the "License");
 *
 * See the NOTICE.txt file distributed with this work for additional
 * information regarding copyright ownership. You may not use this file
 * except in compliance with the License. For usage restrictions see the
 * LICENSE.txt file distributed with this work
 * #L%
 */
package io.netty.util.internal.cert.domain;

import io.netty.util.internal.cert.api.KeyPairInfo;
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

    assertEquals("test", info.name);
    assertEquals("ECDSA", info.algorithm);
    assertNotNull(info.publicKey);
  }
}
