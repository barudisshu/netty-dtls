package info.galudisu.http2_server;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;

/**
 * A HTTP2 negotiation handler
 *
 * @author galudisu
 */
public class Http2OrHttpServerHandler extends ApplicationProtocolNegotiationHandler {

  private static final int MAX_CONTENT_LENGTH = 1024 * 100;

  public Http2OrHttpServerHandler() {
    super(ApplicationProtocolNames.HTTP_2);
  }

  @Override
  protected void configurePipeline(ChannelHandlerContext ctx, String protocol) {
    if (ApplicationProtocolNames.HTTP_2.equals(protocol)) {
      ctx.pipeline().addLast(new Http2ServerHandlerBuilder().build());
      return;
    }
    if (ApplicationProtocolNames.HTTP_1_1.equals(protocol)) {
      ctx.pipeline()
          .addLast(
              new HttpServerCodec(),
              new HttpObjectAggregator(MAX_CONTENT_LENGTH),
              new Http1ServerHandler("ALPN Negotiation"));
      return;
    }
    throw new IllegalStateException("unknown protocol: " + protocol);
  }
}
