package io.netty.util.internal.resources.platform;

import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.epoll.*;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.unix.DomainSocketChannel;
import io.netty.channel.unix.ServerDomainSocketChannel;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import java.util.concurrent.ThreadFactory;

/**
 * {@link DefaultLoop} that uses {@code Epoll} transport.
 *
 * @author Galudisu
 */
public class DefaultLoopEpoll implements DefaultLoop {

  @Override
  @SuppressWarnings("unchecked")
  public <C extends Channel> C getChannel(Class<C> channelClass) {
    if (channelClass.equals(SocketChannel.class)) {
      return (C) new EpollSocketChannel();
    }
    if (channelClass.equals(ServerSocketChannel.class)) {
      return (C) new EpollServerSocketChannel();
    }
    if (channelClass.equals(DatagramChannel.class)) {
      return (C) new EpollDatagramChannel();
    }
    if (channelClass.equals(DomainSocketChannel.class)) {
      return (C) new EpollDomainSocketChannel();
    }
    if (channelClass.equals(ServerDomainSocketChannel.class)) {
      return (C) new EpollServerDomainSocketChannel();
    }
    throw new IllegalArgumentException("Unsupported channel type: " + channelClass.getSimpleName());
  }

  @Override
  @SuppressWarnings("unchecked")
  public <C extends Channel> Class<? extends C> getChannelClass(Class<C> channelClass) {
    if (channelClass.equals(SocketChannel.class)) {
      return (Class<? extends C>) EpollSocketChannel.class;
    }
    if (channelClass.equals(ServerSocketChannel.class)) {
      return (Class<? extends C>) EpollServerSocketChannel.class;
    }
    if (channelClass.equals(DatagramChannel.class)) {
      return (Class<? extends C>) EpollDatagramChannel.class;
    }
    throw new IllegalArgumentException("Unsupported channel type: " + channelClass.getSimpleName());
  }

  @Override
  public String getName() {
    return "epoll";
  }

  @Override
  public EventLoopGroup newEventLoopGroup(int threads, ThreadFactory factory) {
    return new EpollEventLoopGroup(threads, factory);
  }

  @Override
  public boolean supportGroup(EventLoopGroup group) {
    return group instanceof EpollEventLoopGroup;
  }

  static final InternalLogger log = InternalLoggerFactory.getInstance(DefaultLoopEpoll.class);

  static boolean epoll;

  public static boolean isEpoll() {
    return epoll;
  }

  static {
    boolean epollCheck = false;
    try {
      Class.forName("io.netty.channel.epoll.Epoll");
      epollCheck = Epoll.isAvailable();
    } catch (ClassNotFoundException cnfe) {
      // noop
    }
    epoll = epollCheck;
    if (log.isDebugEnabled()) {
      log.debug("Default Epoll support : " + epoll);
    }
  }
}
