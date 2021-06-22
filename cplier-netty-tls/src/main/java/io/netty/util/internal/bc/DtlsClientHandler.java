package io.netty.util.internal.bc;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSTransport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

/** @author gwu */
public class DtlsClientHandler extends DtlsHandler {

  private final DtlsClient mclient;

  public DtlsClientHandler(DtlsClient dtlsClient) {
    this.mclient = dtlsClient;
  }

  @Override
  protected DTLSTransport getDtlsTransport() throws IOException {
    DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
    return clientProtocol.connect(mclient, rawTransport);
  }

  @Override
  public void connect(
      ChannelHandlerContext ctx,
      SocketAddress remoteAddress,
      SocketAddress localAddress,
      ChannelPromise future)
      throws Exception {
    rawTransport.setRemoteAddress((InetSocketAddress) remoteAddress);
    super.connect(ctx, remoteAddress, localAddress, future);
  }
}
