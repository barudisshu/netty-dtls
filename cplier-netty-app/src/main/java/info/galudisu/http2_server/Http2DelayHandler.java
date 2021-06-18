package info.galudisu.http2_server;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.TimeUnit;

/** @author Galudisu */
@Slf4j
public class Http2DelayHandler extends ChannelOutboundHandlerAdapter {

  @Override
  public void flush(ChannelHandlerContext ctx) {
    ctx.executor()
        .schedule(
            () -> {
              try {
                super.flush(ctx);
              } catch (Exception e) {
                log.error("can not schedule response message");
              }
            },
            3,
            TimeUnit.SECONDS);
  }
}
