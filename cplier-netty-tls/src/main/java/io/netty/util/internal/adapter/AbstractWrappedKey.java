package io.netty.util.internal.adapter;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.security.Key;

/**
 * JCE/JDK key base class that wraps a BC native private key.
 *
 * @author Marvin S. Addison
 * @param  <T> Asymmetric key parameters type wrapped by this class.
 */
public abstract class AbstractWrappedKey<T extends AsymmetricKeyParameter> implements Key {
  /** Wrapped key. */
  protected final transient T delegate;

  /**
   * Creates a new instance that wraps the given BC key.
   *
   * @param wrappedKey BC key to wrap.
   */
  public AbstractWrappedKey(final T wrappedKey) {
    if (wrappedKey == null) {
      throw new IllegalArgumentException("Wrapped key cannot be null.");
    }
    delegate = wrappedKey;
  }

  /** @return Null to indicate that encoding is not supported. */
  @Override
  public String getFormat() {
    return null;
  }

  /** @return Null to indicate that encoding is not supported. */
  @Override
  public byte[] getEncoded() {
    return new byte[0];
  }
}
