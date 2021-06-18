package io.netty.util.internal.resources.platform;

import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;

import java.util.concurrent.ThreadFactory;

/**
 * {@link DefaultLoop} that uses {@code NIO} transport.
 *
 * @author galudisu
 */
public class DefaultLoopNio implements DefaultLoop {
  @Override
  @SuppressWarnings("unchecked")
  public <C extends Channel> C getChannel(Class<C> channelClass) {
    if (channelClass.equals(SocketChannel.class)) {
      return (C) new NioSocketChannel();
    }
    if (channelClass.equals(ServerSocketChannel.class)) {
      return (C) new NioServerSocketChannel();
    }
    if (channelClass.equals(DatagramChannel.class)) {
      return (C) new NioDatagramChannel();
    }
    throw new IllegalArgumentException("Unsupported channel type: " + channelClass.getSimpleName());
  }

  @Override
  @SuppressWarnings("unchecked")
  public <C extends Channel> Class<? extends C> getChannelClass(Class<C> channelClass) {
    if (channelClass.equals(SocketChannel.class)) {
      return (Class<? extends C>) NioSocketChannel.class;
    }
    if (channelClass.equals(ServerSocketChannel.class)) {
      return (Class<? extends C>) NioServerSocketChannel.class;
    }
    if (channelClass.equals(DatagramChannel.class)) {
      return (Class<? extends C>) NioDatagramChannel.class;
    }
    throw new IllegalArgumentException("Unsupported channel type: " + channelClass.getSimpleName());
  }

  @Override
  public String getName() {
    return "nio";
  }

  @Override
  public EventLoopGroup newEventLoopGroup(int threads, ThreadFactory factory) {
    return new NioEventLoopGroup(threads, factory);
  }

  @Override
  public boolean supportGroup(EventLoopGroup group) {
    return false;
  }
}
