package info.galudisu.http2_client;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import lombok.extern.slf4j.Slf4j;

/** @author galudisu */
@Slf4j
public final class Http2ClientEventLogger extends ChannelInboundHandlerAdapter {

  @Override
  public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
    log.debug("User Event Triggered: {}", evt);
    ctx.fireUserEventTriggered(evt);
  }
}
