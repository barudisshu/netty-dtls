package io.netty.util.internal.adapter;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

/**
 * JCE/JDK EC public key that wraps the corresponding BC EC public key type, {@link
 * ECPublicKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedECPublicKey extends AbstractWrappedECKey<ECPublicKeyParameters>
    implements ECPublicKey {
  /**
   * Creates a new instance that wraps the given key.
   *
   * @param wrappedKey EC key to wrap.
   */
  public WrappedECPublicKey(final ECPublicKeyParameters wrappedKey) {
    super(wrappedKey);
  }

  @Override
  public ECPoint getW() {
    return new ECPoint(
        delegate.getQ().getXCoord().toBigInteger(), delegate.getQ().getYCoord().toBigInteger());
  }
}
