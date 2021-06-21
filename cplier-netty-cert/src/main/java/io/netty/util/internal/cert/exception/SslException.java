package io.netty.util.internal.cert.exception;

/**
 * A base exception for problems that occur while trying to configure SSL.
 *
 * @author galudisu
 */
public class SslException extends RuntimeException {
  public SslException(String message, Exception cause) {
    super(message, cause);
  }

  public SslException(String message) {
    super(message);
  }

  public SslException(Throwable cause) {
    super(cause);
  }
}
