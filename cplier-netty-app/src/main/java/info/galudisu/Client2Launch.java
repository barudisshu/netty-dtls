package info.galudisu;

import info.galudisu.http2_client.Http2ClientInitializer;
import info.galudisu.http2_client.HttpResponseHandler;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http2.HttpConversionUtil;
import io.netty.handler.ssl.SslContext;
import io.netty.util.AsciiString;
import io.netty.util.CharsetUtil;
import io.netty.util.internal.cert.jsse.SSLContextFactory;
import io.netty.util.internal.resources.platform.DefaultLoopNativeDetector;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

import static io.netty.handler.codec.http.HttpMethod.GET;
import static io.netty.handler.codec.http.HttpMethod.POST;

@Slf4j
public class Client2Launch implements Launch {

  private static final boolean SSL_SUPPORT = true;
  private EventLoopGroup workerGroup;
  private ChannelFuture channelFuture;

  @Override
  public void createEventLoopGroup() {
    workerGroup = buildEventLoopGroup("HTTP-CLIENT");
  }

  @Override
  public void startServer() {
    var initializer = new Http2ClientInitializer(openSslCtx());
    final var bootstrap = new Bootstrap();
    channelFuture =
        bootstrap
            .group(workerGroup)
            .channel(DefaultLoopNativeDetector.INSTANCE.getChannelClass(SocketChannel.class))
            .option(ChannelOption.SO_KEEPALIVE, true)
            .handler(initializer)
            .remoteAddress("localhost", getPort())
            .connect()
            .syncUninterruptibly();

    var channel = channelFuture.channel();
    log.info("Connected to [{}]", getPort());
    var http2SettingsHandler = initializer.getSettingsHandler();
    http2SettingsHandler.awaitSettings(60, TimeUnit.SECONDS);

    log.info("Sending request(s)...");

    // post

    FullHttpRequest request =
        buildPostRequest(
            getSchema(), AsciiString.of("127.0.0.1"), "/proverb", "{\"framework\": \"netty\"}");
    HttpResponseHandler responseHandler = initializer.getResponseHandler();
    var streamId = 3;
    responseHandler.put(streamId, channel.write(request), channel.newPromise());

    request =
        buildPostRequest(
            getSchema(), AsciiString.of("0.0.0.0"), "/json", "{\"framework\": \"disrupt\"}");
    streamId = 5;
    responseHandler.put(streamId, channel.write(request), channel.newPromise());

    // get
    request = buildGetRequest(getSchema(), AsciiString.of("localhost"), "/proverb");
    streamId = 7;
    responseHandler.put(streamId, channel.write(request), channel.newPromise());

    channel.flush();
    String response = responseHandler.awaitResponses(60, TimeUnit.SECONDS);
    log.debug("response msg: {}", response);
    log.info("Finished HTTP/2 request(s)");
  }

  private HttpScheme getSchema() {
    if (SSL_SUPPORT) return HttpScheme.HTTPS;
    else return HttpScheme.HTTP;
  }
  // Create a simple GET request.
  private FullHttpRequest buildGetRequest(HttpScheme scheme, AsciiString hostName, String url) {
    FullHttpRequest request =
        new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, GET, url, Unpooled.EMPTY_BUFFER);
    request.headers().add(HttpHeaderNames.HOST, hostName);
    request.headers().add(HttpConversionUtil.ExtensionHeaderNames.SCHEME.text(), scheme.name());
    request.headers().add(HttpHeaderNames.ACCEPT_ENCODING, HttpHeaderValues.GZIP);
    request.headers().add(HttpHeaderNames.ACCEPT_ENCODING, HttpHeaderValues.DEFLATE);
    return request;
  }

  // Create a simple POST request with a body.
  private FullHttpRequest buildPostRequest(
      HttpScheme scheme, AsciiString hostName, String url, String data) {
    FullHttpRequest request =
        new DefaultFullHttpRequest(
            HttpVersion.HTTP_1_1,
            POST,
            url,
            Unpooled.copiedBuffer(data.getBytes(CharsetUtil.UTF_8)));
    request.headers().add(HttpHeaderNames.HOST, hostName);
    request.headers().add(HttpConversionUtil.ExtensionHeaderNames.SCHEME.text(), scheme.name());
    request.headers().add(HttpHeaderNames.ACCEPT_ENCODING, HttpHeaderValues.GZIP);
    request.headers().add(HttpHeaderNames.ACCEPT_ENCODING, HttpHeaderValues.DEFLATE);
    request.headers().add(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON);
    return request;
  }

  @Override
  public void closeChannel() {
    try {
      channelFuture.channel().close().sync();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  @Override
  public void shutdownGraceFully() {
    workerGroup.shutdownGracefully();
  }

  public static void main(String[] args) {
    var client2Launch = new Client2Launch();
    try {
      client2Launch.createEventLoopGroup();
      client2Launch.startServer();
      client2Launch.closeChannel();
    } finally {
      client2Launch.shutdownGraceFully();
    }
  }

  private int getPort() {
    if (SSL_SUPPORT) return 8443;
    else return 8080;
  }

  private SslContext openSslCtx() {
    SslContext sslCtx = null;
    if (SSL_SUPPORT) {
      try {
        sslCtx =
            SSLContextFactory.generateClientSslContext(
                getPath("openssl/ca.crt"),
                getPath("openssl/client.crt"),
                getPath("openssl/pkcs8_client.key"),
                "client");
      } catch (SSLException e) {
        log.debug("no ssl certificate provided, rollback to http1");
      } catch (IOException e) {
        log.debug("can not read certificate provided, rollback to http1");
      }
    }
    return sslCtx;
  }

  /**
   * @deprecated use {@link Client2Launch#openSslCtx()} instead.
   * @return {@link SslContext}
   */
  @Deprecated(forRemoval = true)
  private SslContext clientSslCtx() { // NOSONAR
    SslContext sslCtx = null;
    if (SSL_SUPPORT) {
      try {
        sslCtx = SSLContextFactory.generateClientSslContext();
      } catch (SSLException e) {
        log.debug("no ssl certificate provided, rollback to http1", e);
      }
    }
    return sslCtx;
  }
}
