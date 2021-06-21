package info.galudisu;

import io.netty.channel.EventLoopGroup;
import io.netty.util.internal.resources.platform.DefaultLoopNativeDetector;
import io.netty.util.internal.resources.thread.LocalThreadFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicInteger;

public interface Dispatch {

  Integer CPU_CORE = Runtime.getRuntime().availableProcessors();

  default EventLoopGroup buildEventLoopGroup(String prefix) {
    return buildEventLoopGroup(true, prefix);
  }

  default EventLoopGroup buildEventLoopGroup(String prefix, boolean isWorker) {
    return buildEventLoopGroup(true, isWorker ? CPU_CORE * 2 : CPU_CORE, prefix);
  }

  default EventLoopGroup buildEventLoopGroup(int threads, String prefix) {
    return buildEventLoopGroup(true, threads, prefix);
  }

  default EventLoopGroup buildEventLoopGroup(boolean daemon, String prefix) {
    return buildEventLoopGroup(daemon, CPU_CORE, prefix);
  }

  default EventLoopGroup buildEventLoopGroup(boolean daemon, String prefix, boolean isWorker) {
    return buildEventLoopGroup(daemon, isWorker ? CPU_CORE * 2 : CPU_CORE, prefix);
  }

  /**
   * Create event-loop-group that depended by platform.
   *
   * @param daemon daemon thread
   * @param threads threads counts
   * @param prefix thread name prefix
   * @return {@link EventLoopGroup}
   */
  default EventLoopGroup buildEventLoopGroup(boolean daemon, int threads, String prefix) {
    final var atomicInteger = new AtomicInteger();
    return DefaultLoopNativeDetector.INSTANCE.newEventLoopGroup(
        threads, new LocalThreadFactory(daemon, atomicInteger, prefix));
  }

  /**
   * Get cert from path into {@link InputStream} which doesn't closed.
   *
   * @param path certificate paths.
   * @return {@link InputStream}
   * @throws IOException io exception
   */
  default InputStream getPath(String path) throws IOException {
    InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
    if (in != null) return new BufferedInputStream(in);
    else throw new IOException("can not read file from path");
  }
}
