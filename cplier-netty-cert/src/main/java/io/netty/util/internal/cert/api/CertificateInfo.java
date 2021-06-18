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
package io.netty.util.internal.cert.api;

/** This DTO encapsulates the information about a certificate */
public class CertificateInfo {

  /** The alias (name) for the certificate */
  public String alias;

  /** The type of the certificate */
  public String type;

  /** The subject for the certificate */
  public String subject;

  /** The algorithm used by the certificate */
  public String algorithm;

  /** The public key for the certificate */
  public byte[] publicKey;
}
