package io.netty.util.internal.cert.bctls.api;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** This DTO encapsulates the information about a certificate */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CertificateInfo {

  /** The alias (name) for the certificate */
  private String alias;

  /** The type of the certificate */
  private String type;

  /** The subject for the certificate */
  private String subject;

  /** The algorithm used by the certificate */
  private String algorithm;

  /** The public key for the certificate */
  private byte[] publicKey;
}
