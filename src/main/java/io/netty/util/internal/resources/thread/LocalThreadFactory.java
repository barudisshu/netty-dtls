package io.netty.util.internal.resources.thread;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * ThreadFactory used by {@link io.netty.channel.EventLoopGroup}
 *
 * @author Galudisu
 */
public final class LocalThreadFactory implements ThreadFactory {
  final boolean daemon;
  final AtomicInteger counter;
  final String prefix;

  public LocalThreadFactory(boolean daemon, AtomicInteger counter, String prefix) {
    this.daemon = daemon;
    this.counter = counter;
    this.prefix = prefix;
  }

  @Override
  public Thread newThread(Runnable runnable) {
    Thread thread = new LocalThread(runnable);
    thread.setDaemon(daemon);
    thread.setName(prefix + "-" + counter.incrementAndGet());
    return thread;
  }
}
