package io.netty.util.internal.dtls.jsse;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandler;
import io.netty.channel.ChannelOutboundHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.internal.tls.DTLSHandler;

public interface InternalDTLSHandler
    extends DTLSHandler, ChannelInboundHandler, ChannelOutboundHandler {

  Future<Void> close(ChannelHandlerContext ctx, boolean sendData);
}
