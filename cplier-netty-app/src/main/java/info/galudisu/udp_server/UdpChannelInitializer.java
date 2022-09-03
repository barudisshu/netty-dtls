package info.galudisu.udp_server;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.DatagramChannel;
import io.netty.util.internal.bc.DtlsServer;
import io.netty.util.internal.bc.DtlsServerHandler;
import io.netty.util.internal.dtls.adapter.JdkDtlsEngineAdapter;
import io.netty.util.internal.dtls.jsse.ServerDTLSHandler;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

@Slf4j
public class UdpChannelInitializer extends ChannelInitializer<DatagramChannel> {

  private final SSLContext sslContext;
  private final boolean isJdkSsl;

  public UdpChannelInitializer(SSLContext sslContext, boolean isJdkSsl) {
    this.sslContext = sslContext;
    this.isJdkSsl = isJdkSsl;
  }

  @Override
  protected void initChannel(DatagramChannel ch) {
    ChannelPipeline pipeline = ch.pipeline();

    if (isJdkSsl) {
      // jdk
      var engine = createSSLEngine(sslContext);
      pipeline.addLast(new ServerDTLSHandler(new JdkDtlsEngineAdapter(engine)));
    } else {
      // bck
      pipeline.addLast(new DtlsServerHandler(new DtlsServer()));
    }
    pipeline.addLast(new UdpServerHandler());
    pipeline.addLast(new UdpSenderHandler());
  }

  /**
   * Using JDK ssl if you need
   *
   * <pre>{@code
   * var engine = createSSLEngine(sslContext);
   * pipeline.addLast(new ServerDTLSHandler(new JdkDtlsEngineAdapter(engine)));
   * }</pre>
   *
   * @param sslContext
   * @return
   * @throws SSLException
   */
  private SSLEngine createSSLEngine(SSLContext sslContext) {
    var engine = sslContext.createSSLEngine();
    engine.setUseClientMode(false);
    var sslParameters = engine.getSSLParameters();
    sslParameters.setNeedClientAuth(false);
    engine.setSSLParameters(sslParameters);
    return engine;
  }
}
