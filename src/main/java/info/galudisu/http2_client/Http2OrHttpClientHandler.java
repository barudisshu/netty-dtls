package info.galudisu.http2_client;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.http2.HttpToHttp2ConnectionHandler;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;

/** @author Galudisu */
public class Http2OrHttpClientHandler extends ApplicationProtocolNegotiationHandler {
  private final HttpToHttp2ConnectionHandler connectionHandler;
  private final Http2SettingsHandler settingsHandler;
  private final HttpResponseHandler responseHandler;

  public Http2OrHttpClientHandler(
      HttpToHttp2ConnectionHandler connectionHandler,
      Http2SettingsHandler settingsHandler,
      HttpResponseHandler responseHandler) {
    super(ApplicationProtocolNames.HTTP_2);
    this.connectionHandler = connectionHandler;
    this.settingsHandler = settingsHandler;
    this.responseHandler = responseHandler;
  }

  @Override
  protected void configurePipeline(ChannelHandlerContext ctx, String protocol) {
    if (ApplicationProtocolNames.HTTP_2.equals(protocol)) {
      ChannelPipeline p = ctx.pipeline();
      p.addLast(connectionHandler);
      p.addLast(settingsHandler, responseHandler);
      return;
    }
    ctx.close();
    throw new IllegalStateException("unknown protocol: " + protocol);
  }
}
