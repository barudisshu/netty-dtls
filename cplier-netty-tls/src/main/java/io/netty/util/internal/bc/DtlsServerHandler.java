package io.netty.util.internal.bc;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.DatagramPacket;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;

import java.io.IOException;

/** @author gwu */
public class DtlsServerHandler extends DtlsHandler {

  private final DtlsServer mserver;

  public DtlsServerHandler(DtlsServer dtlsServer) {
    this.mserver = dtlsServer;
  }

  @Override
  protected DTLSTransport getDtlsTransport() throws IOException {
    var serverProtocol = new DTLSServerProtocol();
    return serverProtocol.accept(mserver, rawTransport);
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object obj) throws Exception {
    if (obj instanceof DatagramPacket) {
      DatagramPacket msg = (DatagramPacket) obj;
      // day0

      rawTransport.setRemoteAddress(msg.sender());
    }

    super.channelRead(ctx, obj);
  }
}
