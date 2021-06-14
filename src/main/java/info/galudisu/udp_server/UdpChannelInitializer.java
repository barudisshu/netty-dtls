package info.galudisu.udp_server;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.DatagramChannel;

public class UdpChannelInitializer extends ChannelInitializer<DatagramChannel> {
  @Override
  protected void initChannel(DatagramChannel ch) {
    ChannelPipeline pipeline = ch.pipeline();
    pipeline.addLast(new UdpServerHandler());
    pipeline.addLast(new UdpSenderHandler());
  }
}
