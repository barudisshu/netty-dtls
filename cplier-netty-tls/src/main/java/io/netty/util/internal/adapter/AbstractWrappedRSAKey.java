package io.netty.util.internal.adapter;

import org.bouncycastle.crypto.params.RSAKeyParameters;

import java.math.BigInteger;

/**
 * Base class for RSA wrapped keys.
 *
 * @author Marvin S. Addison
 * @param  <T> RSA key parameters type handled by this class.
 */
public abstract class AbstractWrappedRSAKey<T extends RSAKeyParameters>
    extends AbstractWrappedKey<T> {
  /** RSA algorithm name. */
  private static final String ALGORITHM = "RSA";

  /**
   * Creates a new instance that wraps the given key.
   *
   * @param wrappedKey Key to wrap.
   */
  public AbstractWrappedRSAKey(final T wrappedKey) {
    super(wrappedKey);
  }

  /** @return Gets the RSA modulus. */
  public BigInteger getModulus() {
    return delegate.getModulus();
  }

  @Override
  public String getAlgorithm() {
    return ALGORITHM;
  }
}
