package io.netty.util.internal.cert.bctls.api;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** This DTO encapsulates the information about a key pair */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class KeyPairInfo {

  /** The name of the key pair */
  private String name;

  /** The algorithm used by this key pair */
  private String algorithm;

  /** The public key for this key pair */
  private byte[] publicKey;
}
