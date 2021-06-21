package info.galudisu;

import info.galudisu.udp_server.UdpChannelInitializer;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.util.internal.cert.jsse.SSLContextFactory;
import io.netty.util.internal.resources.platform.DefaultLoopNativeDetector;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static io.netty.channel.unix.UnixChannelOption.SO_REUSEPORT;

/** @author galudisu */
@Slf4j
public class UdpLaunch implements Launch {

  private EventLoopGroup channelGroup;
  private static final List<ChannelFuture> channelFutures = new CopyOnWriteArrayList<>();

  public void createEventLoopGroup() {
    channelGroup = buildEventLoopGroup("UDP-CHANNEL");
  }

  public void startServer() {
    try {
      final var bootstrap = new Bootstrap();
      bootstrap
          .group(channelGroup)
          .option(ChannelOption.SO_BROADCAST, true)
          .option(ChannelOption.SO_REUSEADDR, true)
          .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
          .channel(DefaultLoopNativeDetector.INSTANCE.getChannelClass(DatagramChannel.class))
          .handler(new UdpChannelInitializer(openSslCtx()));

      if (DefaultLoopNativeDetector.IS_EPOLL_OPEN) {
        bootstrap.option(SO_REUSEPORT, true);
        for (var i = 0; i < CPU_CORE; i++) {
          var channelFuture = bootstrap.bind(1314).sync();
          channelFutures.add(channelFuture);
        }
      } else {
        var channelFuture = bootstrap.bind(1314).sync();
        channelFutures.add(channelFuture);
      }

      log.info("http2 server start...");
    } catch (InterruptedException e) {
      log.error("http2 server error", e);
      Thread.currentThread().interrupt();
    }
  }

  private SSLContext openSslCtx() {
    SSLContext sslCtx = null;
    try {
      sslCtx =
          SSLContextFactory.generateDTLSContext(
              getPath("openssl/ca.crt"),
              getPath("openssl/server.crt"),
              getPath("openssl/pkcs8_server.key"),
              "server");
    } catch (IOException e) {
      log.debug("rollback to udp");
    }

    return sslCtx;
  }

  public void closeChannel() {
    try {
      for (ChannelFuture channelFuture : channelFutures) {
        channelFuture.channel().closeFuture().sync();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  public void shutdownGraceFully() {
    channelGroup.shutdownGracefully();
  }

  public static void main(String[] args) {
    var udpLaunch = new UdpLaunch();
    try {
      udpLaunch.createEventLoopGroup();
      udpLaunch.startServer();
      udpLaunch.closeChannel();
    } finally {
      udpLaunch.shutdownGraceFully();
    }
  }
}
