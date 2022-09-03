package io.netty.util.internal.adapter;

import org.bouncycastle.crypto.params.DSAKeyParameters;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;

public abstract class AbstractWrappedDSAKey<T extends DSAKeyParameters>
    extends AbstractWrappedKey<T> {
  /** DSA algorithm name. */
  private static final String ALGORITHM = "DSA";

  /**
   * Creates a new instance that wraps the given key.
   *
   * @param wrappedKey Key to wrap.
   */
  public AbstractWrappedDSAKey(final T wrappedKey) {
    super(wrappedKey);
  }

  /** @return DSA key parameters. */
  public DSAParams getParams() {
    return new DSAParams() {
      @Override
      public BigInteger getP() {
        return delegate.getParameters().getP();
      }

      @Override
      public BigInteger getQ() {
        return delegate.getParameters().getQ();
      }

      @Override
      public BigInteger getG() {
        return delegate.getParameters().getG();
      }
    };
  }

  @Override
  public String getAlgorithm() {
    return ALGORITHM;
  }
}
