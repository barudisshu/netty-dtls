package io.netty.util.internal.resources.platform;

import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;

import java.util.concurrent.ThreadFactory;

/**
 * The I/O multiplexing(select and poll) transport.
 *
 * <pre>{@code
 * - NIO: Windows
 * - Epoll: Linux
 * - KQueue: FreeBSD
 * }</pre>
 *
 * We only care about NIO and Epoll here.
 *
 * @author Galudisu
 */
public interface DefaultLoop {

  <C extends Channel> C getChannel(Class<C> channelClass);

  <C extends Channel> Class<? extends C> getChannelClass(Class<C> channelClass);

  String getName();

  EventLoopGroup newEventLoopGroup(int threads, ThreadFactory factory);

  boolean supportGroup(EventLoopGroup group);
}
