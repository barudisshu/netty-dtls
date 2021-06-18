package io.netty.util.internal.resources.platform;

/**
 * Native transport detector
 *
 * @author Galudisu
 */
public final class DefaultLoopNativeDetector {

  public static final DefaultLoop INSTANCE;
  public static final DefaultLoop NIO;
  public static final boolean IS_EPOLL_OPEN;

  static {
    NIO = new DefaultLoopNio();

    if (DefaultLoopEpoll.isEpoll()) {
      IS_EPOLL_OPEN = true;
      INSTANCE = new DefaultLoopEpoll();
    } else {
      IS_EPOLL_OPEN = false;
      INSTANCE = NIO;
    }
  }

  private DefaultLoopNativeDetector() {
    throw new UnsupportedOperationException("not support");
  }
}
