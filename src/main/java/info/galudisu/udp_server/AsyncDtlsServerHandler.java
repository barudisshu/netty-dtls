package info.galudisu.udp_server;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;
import lombok.extern.slf4j.Slf4j;

/** @author Galudisu */
@Slf4j
public class AsyncDtlsServerHandler extends ApplicationProtocolNegotiationHandler {

  public AsyncDtlsServerHandler() {
    super("dtls");
  }

  @Override
  protected void configurePipeline(ChannelHandlerContext ctx, String protocol) {
    log.debug("very nice that receive: {} protocol", protocol);
  }
}
