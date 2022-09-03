package info.galudisu.udp_server;

import info.galudisu.Hightlight;
import info.galudisu.Proverb;
import info.galudisu.ConsoleOutput;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;
import io.netty.util.CharsetUtil;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class UdpServerHandler extends SimpleChannelInboundHandler<DatagramPacket> {

  @Override
  protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket datagramPacket) {
    var req = datagramPacket.content().toString(CharsetUtil.UTF_8);
    log.debug(
        "\n{}--- UDP: Receiving message from client ---{}\n{}{}{}\n",
        Hightlight.GREEN,
        Hightlight.RESET,
        Hightlight.YELLOW,
        ConsoleOutput.ofPretty(req),
        Hightlight.RESET);
    ctx.fireChannelRead(new Proverb(req));
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
    log.error("exception cause", cause);
    ctx.close();
  }
}
