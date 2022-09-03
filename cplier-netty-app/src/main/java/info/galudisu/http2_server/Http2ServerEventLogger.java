package info.galudisu.http2_server;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import lombok.extern.slf4j.Slf4j;

/** Class that logs any User Events triggered on this channel. */
@Slf4j
public final class Http2ServerEventLogger extends ChannelInboundHandlerAdapter {

  @Override
  public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
    log.debug("User Event Triggered: {}", evt);
    ctx.fireUserEventTriggered(evt);
  }
}
