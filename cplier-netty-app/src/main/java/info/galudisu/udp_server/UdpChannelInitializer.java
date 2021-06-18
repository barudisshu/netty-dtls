package info.galudisu.udp_server;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.DatagramChannel;
import io.netty.util.internal.dtls.adapter.JdkDtlsEngineAdapter;
import io.netty.util.internal.dtls.jsse.ParemusServerDTLSHandler;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

public class UdpChannelInitializer extends ChannelInitializer<DatagramChannel> {

  private final SSLContext sslContext;

  public UdpChannelInitializer(SSLContext sslContext) {
    this.sslContext = sslContext;
  }

  @Override
  protected void initChannel(DatagramChannel ch) {
    ChannelPipeline pipeline = ch.pipeline();

    SSLEngine engine = sslContext.createSSLEngine();
    SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
    sslParameters.setNeedClientAuth(false);
    engine.setSSLParameters(sslParameters);
    engine.setUseClientMode(false);
    pipeline.addLast(new ParemusServerDTLSHandler(new JdkDtlsEngineAdapter(engine)));
    pipeline.addLast(new UdpServerHandler());
    pipeline.addLast(new UdpSenderHandler());
  }
}
