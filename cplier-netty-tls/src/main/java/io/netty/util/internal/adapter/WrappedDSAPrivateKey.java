package io.netty.util.internal.adapter;

import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;

import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;

/**
 * JCE/JDK DSA private key that wraps the corresponding BC DSA private key type, {@link
 * DSAPrivateKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedDSAPrivateKey extends AbstractWrappedDSAKey<DSAPrivateKeyParameters>
    implements DSAPrivateKey {
  /**
   * Creates a new instance that wraps the given BC DSA private key.
   *
   * @param parameters BC DSA private key.
   */
  public WrappedDSAPrivateKey(final DSAPrivateKeyParameters parameters) {
    super(parameters);
  }

  /** {@inheritDoc} */
  @Override
  public BigInteger getX() {
    return delegate.getX();
  }
}
