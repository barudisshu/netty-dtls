package info.galudisu.http2_client;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpClientUpgradeHandler;
import io.netty.handler.codec.http2.*;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SslContext;

import static io.netty.handler.logging.LogLevel.DEBUG;

/** @author galudisu */
public class Http2ClientInitializer extends ChannelInitializer<SocketChannel> {
  private static final Http2FrameLogger HTTP_2_FRAME_LOGGER =
      new Http2FrameLogger(DEBUG, Http2ClientInitializer.class);

  private final SslContext sslCtx;
  private final int maxContentLength;
  private HttpToHttp2ConnectionHandler connectionHandler;
  private HttpResponseHandler responseHandler;
  private Http2SettingsHandler settingsHandler;

  public Http2ClientInitializer(SslContext sslCtx) {
    this(sslCtx, Integer.MAX_VALUE);
  }

  public Http2ClientInitializer(SslContext sslCtx, int maxContentLength) {
    if (maxContentLength < 0) {
      throw new IllegalArgumentException(
          "maxHttpContentLength (expected >= 0): " + maxContentLength);
    }
    this.sslCtx = sslCtx;
    this.maxContentLength = maxContentLength;
  }

  @Override
  protected void initChannel(SocketChannel ch) {
    final Http2Connection connection = new DefaultHttp2Connection(false);
    connectionHandler =
        new HttpToHttp2ConnectionHandlerBuilder()
            .frameListener(
                new DelegatingDecompressorFrameListener(
                    connection,
                    new InboundHttp2ToHttpAdapterBuilder(connection)
                        .maxContentLength(maxContentLength)
                        .propagateSettings(true)
                        .build()))
            .frameLogger(HTTP_2_FRAME_LOGGER)
            .connection(connection)
            .build();
    responseHandler = new HttpResponseHandler();
    settingsHandler = new Http2SettingsHandler(ch.newPromise());
    if (sslCtx != null) {
      configureSsl(ch);
    } else {
      configureClearText(ch);
    }
  }

  public Http2SettingsHandler getSettingsHandler() {
    return settingsHandler;
  }

  public HttpResponseHandler getResponseHandler() {
    return responseHandler;
  }

  /** Configure the pipeline for TLS NPN negotiation to HTTP/2. */
  private void configureSsl(SocketChannel ch) {
    ChannelPipeline pipeline = ch.pipeline();
    pipeline.addLast(new LoggingHandler());
    pipeline.addLast(sslCtx.newHandler(ch.alloc()));
    pipeline.addLast(
        new Http2OrHttpClientHandler(connectionHandler, settingsHandler, responseHandler));
  }

  /** Configure the pipeline for a cleartext upgrade from HTTP to HTTP/2. */
  private void configureClearText(SocketChannel ch) {
    var sourceCodec = new HttpClientCodec();
    var upgradeCodec = new Http2ClientUpgradeCodec(connectionHandler);
    var upgradeHandler =
        new HttpClientUpgradeHandler(sourceCodec, upgradeCodec, 65536);
    ChannelPipeline pipeline = ch.pipeline();
    pipeline.addLast(new LoggingHandler());
    pipeline.addLast(sourceCodec);
    pipeline.addLast(upgradeHandler);
    pipeline.addLast(new HttpClientDowngradeHandler());
    pipeline.addLast(settingsHandler, responseHandler);
    ch.pipeline().addLast(new Http2ClientEventLogger());
  }
}
