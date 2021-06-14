package info.galudisu;

import info.galudisu.http2_server.HttpChannelInitializer;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.*;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.util.internal.resources.openssl.SSLContextFactory;
import io.netty.util.internal.resources.platform.DefaultLoopNativeDetector;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.security.cert.CertificateException;

/** @author Galudisu */
@Slf4j
public class Http2Launch implements Launch {

  private EventLoopGroup httpServerBossGroup;
  private EventLoopGroup httpServerWorkerGroup;

  private ChannelFuture channelFuture;

  public void createEventLoopGroup() {
    httpServerBossGroup = createEventLoopGroup(true, CPU_CORE, "HTTP-BOSS");
    httpServerWorkerGroup = createEventLoopGroup(false, CPU_CORE * 2, "HTTP-WORKER");
  }

  public void startServer() {
    try {
      final ServerBootstrap serverBootstrap = new ServerBootstrap();
      channelFuture =
          serverBootstrap
              .group(httpServerBossGroup, httpServerWorkerGroup)
              .option(ChannelOption.SO_BACKLOG, 128)
              .channel(
                  DefaultLoopNativeDetector.INSTANCE.getChannelClass(ServerSocketChannel.class))
              .handler(new LoggingHandler(LogLevel.DEBUG))
              .childHandler(new HttpChannelInitializer(openSslCtx()))
              .bind("localhost", getPort())
              .sync();
      log.info("http2 server start...");
    } catch (InterruptedException e) {
      log.error("http2 server error", e);
      Thread.currentThread().interrupt();
    }
  }

  private static final boolean SSL_SUPPORT = true;

  private int getPort() {
    if (SSL_SUPPORT) return 8443;
    else return 8080;
  }

  private SslContext openSslCtx() {
    SslContext sslCtx = null;
    if (SSL_SUPPORT) {
      try {
        sslCtx =
            SSLContextFactory.generateServerSslContext(getPath("openssl/server.pem"), getPath("openssl/server.key"));
      } catch (SSLException e) {
        log.debug("no ssl certificate provided, rollback to http1");
      } catch (IOException e) {
        log.debug("cannot read ssl certificate provided, rollback to http1");
      }
    }
    return sslCtx;
  }

  @Deprecated
  private SslContext sslCtx() {
    SslContext sslCtx = null;
    if (SSL_SUPPORT) {
      try {
        SelfSignedCertificate ssc = new SelfSignedCertificate();
        sslCtx =
            SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey())
                .sslProvider(SslProvider.JDK)
                .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                .applicationProtocolConfig(
                    new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2,
                        ApplicationProtocolNames.HTTP_1_1))
                .build();
      } catch (CertificateException | SSLException e) { // NOSONAR
        log.debug("no ssl certificate provided, rollback to http1");
      }
    }
    return sslCtx;
  }

  public void closeChannel() {
    try {
      channelFuture.channel().closeFuture().sync();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  public void shutdownGraceFully() {
    httpServerBossGroup.shutdownGracefully();
    httpServerWorkerGroup.shutdownGracefully();
  }

  public static void main(String[] args) {
    Http2Launch http2Launch = new Http2Launch();
    try {
      http2Launch.createEventLoopGroup();
      http2Launch.startServer();
      http2Launch.closeChannel();
    } finally {
      http2Launch.shutdownGraceFully();
    }
  }
}
