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

import io.netty.util.internal.cert.api.CertificateInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Map;

import static java.time.Duration.ofHours;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class KeyStoreManagerTest {

  private final BouncyCastleProvider provider = new BouncyCastleProvider();
  private final SecureRandom secureRandom = new SecureRandom();

  private KeyPairManager keyPairManager;
  private CertificateGenerator certificateGenerator;

  @TempDir Path tempFolder;

  @BeforeEach
  void setUp() {
    keyPairManager = new KeyPairManager(tempFolder, provider, secureRandom);
    certificateGenerator = new CertificateGenerator(provider, secureRandom);
  }

  @Test
  void testCreateKeyStore() {

    KeyStoreManager ksm = new KeyStoreManager(tempFolder, provider, secureRandom);

    KeyPair keyPair = keyPairManager.newKeyPair("TEST");

    Certificate certificate =
        certificateGenerator.generateRootCertificate(keyPair, "TEST_CERT", ofHours(1));

    assertTrue(ksm.listKeyStores().isEmpty());

    ksm.createKeyStore("TEST_STORE", keyPair, new Certificate[] {certificate});

    Map<String, CertificateInfo> stores = ksm.listKeyStores();
    assertEquals(1, stores.size());

    CertificateInfo info = stores.get("TEST_STORE");
    assertNotNull(info);

    assertEquals("test_store", info.alias);
    assertEquals("TEST_CERT", info.subject);
    assertEquals(keyPair.getPublic().getAlgorithm(), info.algorithm);
    assertArrayEquals(keyPair.getPublic().getEncoded(), info.publicKey);
  }
}
