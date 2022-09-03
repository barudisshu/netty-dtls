package info.galudisu.udp_server;

import info.galudisu.Proverb;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class UdpSenderHandler extends SimpleChannelInboundHandler<Proverb> {

  @Override
  protected void channelRead0(ChannelHandlerContext channelHandlerContext, Proverb proverb) {
    log.debug("receiving decode msg: {}", proverb);
  }
}
