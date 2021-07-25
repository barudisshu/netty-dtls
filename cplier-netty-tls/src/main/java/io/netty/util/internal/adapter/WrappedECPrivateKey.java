package io.netty.util.internal.adapter;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;

/**
 * JCE/JDK EC private key that wraps the corresponding BC EC private key type, {@link
 * ECPrivateKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedECPrivateKey extends AbstractWrappedECKey<ECPrivateKeyParameters>
    implements ECPrivateKey {
  /**
   * Creates a new instance that wraps the given key.
   *
   * @param wrappedKey EC key to wrap.
   */
  public WrappedECPrivateKey(final ECPrivateKeyParameters wrappedKey) {
    super(wrappedKey);
  }

  /** {@inheritDoc} */
  @Override
  public BigInteger getS() {
    return delegate.getD();
  }
}
