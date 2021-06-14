package io.netty.util.internal.resources.openssl;

/**
 * A base exception for problems that occur while trying to configure SSL.
 *
 * @author ehcayen
 */
public class SslConfigException extends RuntimeException {
  public SslConfigException(String message, Exception cause) {
    super(message, cause);
  }

  public SslConfigException(String message) {
    super(message);
  }
}
