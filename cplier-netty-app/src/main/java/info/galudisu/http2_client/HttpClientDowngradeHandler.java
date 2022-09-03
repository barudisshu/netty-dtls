package info.galudisu.http2_client;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;

import java.net.InetSocketAddress;

/** @author galudisu */
public class HttpClientDowngradeHandler extends ChannelInboundHandlerAdapter {
  @Override
  public void channelActive(ChannelHandlerContext ctx) {
    var upgradeRequest =
        new DefaultFullHttpRequest(
            HttpVersion.HTTP_1_1, HttpMethod.GET, "/", Unpooled.EMPTY_BUFFER);
    InetSocketAddress remote = (InetSocketAddress) ctx.channel().remoteAddress();
    var hostString = remote.getHostString();
    if (hostString == null) {
      hostString = remote.getAddress().getHostAddress();
    }
    upgradeRequest.headers().set(HttpHeaderNames.HOST, hostString + ':' + remote.getPort());
    ctx.writeAndFlush(upgradeRequest);
    ctx.fireChannelActive();
    ctx.pipeline().remove(this);
  }
}
