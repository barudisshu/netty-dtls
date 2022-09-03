package io.netty.util.internal.adapter;

import org.bouncycastle.crypto.params.DSAPublicKeyParameters;

import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;

/**
 * JCE/JDK DSA public key that wraps the corresponding BC DSA public key type, {@link
 * DSAPublicKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedDSAPublicKey extends AbstractWrappedDSAKey<DSAPublicKeyParameters>
    implements DSAPublicKey {
  /**
   * Creates a new instance that wraps the given key.
   *
   * @param wrappedKey DSA key to wrap.
   */
  public WrappedDSAPublicKey(final DSAPublicKeyParameters wrappedKey) {
    super(wrappedKey);
  }

  /** {@inheritDoc} */
  @Override
  public BigInteger getY() {
    return delegate.getY();
  }
}
