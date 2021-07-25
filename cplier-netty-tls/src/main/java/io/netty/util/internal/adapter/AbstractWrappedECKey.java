package io.netty.util.internal.adapter;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * Base class for wrapped EC keys.
 *
 * @author Marvin S. Addison
 * @param  <T> EC key parameters type.
 */
public abstract class AbstractWrappedECKey<T extends ECKeyParameters>
    extends AbstractWrappedKey<T> {
  /** Elliptic curve algorithm name. */
  private static final String ALGORITHM = "EC";

  /**
   * Creates a new instance that wraps the given key.
   *
   * @param wrappedKey Key to wrap.
   */
  public AbstractWrappedECKey(final T wrappedKey) {
    super(wrappedKey);
  }

  /** @return EC domain parameters. */
  public ECParameterSpec getParams() {
    final ECDomainParameters params = delegate.getParameters();
    return new ECParameterSpec(
        EC5Util.convertCurve(params.getCurve(), params.getSeed()),
        new ECPoint(
            params.getG().getXCoord().toBigInteger(), params.getG().getYCoord().toBigInteger()),
        params.getN(),
        params.getH().intValue());
  }

  @Override
  public String getAlgorithm() {
    return ALGORITHM;
  }
}
