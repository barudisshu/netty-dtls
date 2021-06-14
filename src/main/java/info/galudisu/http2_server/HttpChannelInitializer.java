package info.galudisu.http2_server;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpServerUpgradeHandler;
import io.netty.handler.codec.http2.CleartextHttp2ServerUpgradeHandler;
import io.netty.handler.ssl.SslContext;

public class HttpChannelInitializer extends ChannelInitializer<SocketChannel> {

  private final SslContext sslContext;
  private final int maxHttpContentLength;

  public HttpChannelInitializer(SslContext sslCtx) {
    this(sslCtx, 16 * 1024);
  }

  public HttpChannelInitializer(SslContext sslCtx, int maxHttpContentLength) {
    if (maxHttpContentLength < 0) {
      throw new IllegalArgumentException(
          "maxHttpContentLength (expected >= 0): " + maxHttpContentLength);
    }
    this.sslContext = sslCtx;
    this.maxHttpContentLength = maxHttpContentLength;
  }

  @Override
  protected void initChannel(SocketChannel ch) {
    if (sslContext != null) {
      configureSsl(ch);
    } else {
      configureClearText(ch);
    }
  }

  /** Configure the pipeline for TLS NPN negotiation to HTTP/2. */
  private void configureSsl(SocketChannel ch) {
    ChannelPipeline pipeline = ch.pipeline();
    pipeline.addLast(sslContext.newHandler(ch.alloc()));
    pipeline.addLast(new Http2OrHttpServerHandler());
    pipeline.addFirst(new Http2DelayHandler());
  }

  /** Configure the pipeline for a cleartext upgrade from HTTP to HTTP/2.0 */
  private void configureClearText(SocketChannel ch) {
    final ChannelPipeline p = ch.pipeline();
    final HttpServerCodec httpServerCodec = new HttpServerCodec();
    p.addLast(
        new CleartextHttp2ServerUpgradeHandler(
            httpServerCodec,
            new HttpServerUpgradeHandler(httpServerCodec, new HttpUpgradeCodecFactory()),
            new Http2ServerHandlerBuilder().build()));
    p.addLast(new HttpServerDowngradeHandler(maxHttpContentLength));
    p.addLast(new Http2ServerEventLogger());
    p.addFirst(new Http2DelayHandler());
  }
}
