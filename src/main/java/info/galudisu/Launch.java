package info.galudisu;

import io.netty.channel.EventLoopGroup;
import io.netty.util.internal.resources.platform.DefaultLoopNativeDetector;
import io.netty.util.internal.resources.thread.LocalThreadFactory;
import org.apache.commons.lang3.SystemUtils;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

public interface Launch {

  Integer CPU_CORE = Runtime.getRuntime().availableProcessors();

  void createEventLoopGroup();

  void startServer();

  void closeChannel();

  void shutdownGraceFully();

  default EventLoopGroup createEventLoopGroup(boolean daemon, int threads, String prefix) {
    final AtomicInteger atomicInteger = new AtomicInteger();
    return DefaultLoopNativeDetector.INSTANCE.newEventLoopGroup(
        threads, new LocalThreadFactory(daemon, atomicInteger, prefix));
  }

  default Path getPath(String path) throws UnsupportedEncodingException {
    return Paths.get(
        convertPath(
            Objects.requireNonNull(Thread.currentThread().getContextClassLoader().getResource(path))
                .getPath()));
  }

  default String convertPath(String path) throws UnsupportedEncodingException {
    path = java.net.URLDecoder.decode(path, StandardCharsets.UTF_8.name());
    if (SystemUtils.IS_OS_WINDOWS && path.startsWith("/")) {
      return path.substring(1);
    }
    return path;
  }
}
