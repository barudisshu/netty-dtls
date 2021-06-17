package info.galudisu.udp_server;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.DatagramChannel;
import io.netty.handler.ssl.OpenSslContext;
import io.netty.handler.ssl.OpenSslServerContext;
import io.netty.handler.ssl.SslContext;

public class UdpChannelInitializer extends ChannelInitializer<DatagramChannel> {

  private final SslContext sslContext;

  public UdpChannelInitializer(SslContext sslContext) {
    this.sslContext = sslContext;
  }

  @Override
  protected void initChannel(DatagramChannel ch) {
    ChannelPipeline pipeline = ch.pipeline();
    pipeline.addLast(sslContext.newHandler(ch.alloc()));
    pipeline.addLast(new AsyncDtlsServerHandler());
    pipeline.addLast(new UdpServerHandler());
    pipeline.addLast(new UdpSenderHandler());
  }
}
