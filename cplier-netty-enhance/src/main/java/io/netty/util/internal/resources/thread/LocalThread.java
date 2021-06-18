package io.netty.util.internal.resources.thread;

import io.netty.util.concurrent.FastThreadLocalThread;

/** @author Galudisu */
final class LocalThread extends FastThreadLocalThread {
  public LocalThread(Runnable target) {
    super(target);
  }
}
