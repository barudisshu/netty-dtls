package info.galudisu.http2_server;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpMessage;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.util.ReferenceCountUtil;
import lombok.extern.slf4j.Slf4j;

/** @author galudisu */
@Slf4j
public class HttpServerDowngradeHandler extends SimpleChannelInboundHandler<HttpMessage> {

  private final int maxHttpContentLength;

  public HttpServerDowngradeHandler(int maxHttpContentLength) {
    this.maxHttpContentLength = maxHttpContentLength;
  }

  @Override
  protected void channelRead0(ChannelHandlerContext ctx, HttpMessage msg) {
    log.debug("Directly talking: {} (no upgrade was attempted)", msg.protocolVersion());
    ChannelPipeline pipeline = ctx.pipeline();
    pipeline.addAfter(ctx.name(), null, new Http1ServerHandler("Direct. No Upgrade Attempted."));
    pipeline.replace(this, null, new HttpObjectAggregator(maxHttpContentLength));
    ctx.fireChannelRead(ReferenceCountUtil.retain(msg));
  }
}
