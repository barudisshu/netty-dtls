package info.galudisu;

import io.netty.channel.EventLoopGroup;
import io.netty.util.internal.resources.platform.DefaultLoopNativeDetector;
import io.netty.util.internal.resources.thread.LocalThreadFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicInteger;

public interface Dispatch {
  default EventLoopGroup createEventLoopGroup(boolean daemon, int threads, String prefix) {
    final AtomicInteger atomicInteger = new AtomicInteger();
    return DefaultLoopNativeDetector.INSTANCE.newEventLoopGroup(
        threads, new LocalThreadFactory(daemon, atomicInteger, prefix));
  }

  default InputStream getPath(String path) throws IOException {
    InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
    if (in != null) return new BufferedInputStream(in);
    else throw new IOException("can not read file from path");
  }
}
