package io.netty.util.internal.adapter;

import org.bouncycastle.crypto.params.RSAKeyParameters;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/**
 * JCE/JDK RSA public key that wraps the corresponding BC RSA public key type, {@link
 * RSAKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedRSAPublicKey extends AbstractWrappedRSAKey<RSAKeyParameters>
    implements RSAPublicKey {
  /**
   * Creates a new instance that wraps the given key.
   *
   * @param wrappedKey RSA key to wrap.
   */
  public WrappedRSAPublicKey(final RSAKeyParameters wrappedKey) {
    super(wrappedKey);
  }

  /** {@inheritDoc} */
  @Override
  public BigInteger getPublicExponent() {
    return delegate.getExponent();
  }
}
