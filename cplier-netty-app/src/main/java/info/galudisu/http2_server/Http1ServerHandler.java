package info.galudisu.http2_server;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpUtil;
import lombok.extern.slf4j.Slf4j;

import static io.netty.handler.codec.http.HttpHeaderNames.*;
import static io.netty.handler.codec.http.HttpHeaderValues.CLOSE;
import static io.netty.handler.codec.http.HttpHeaderValues.KEEP_ALIVE;
import static io.netty.handler.codec.http.HttpResponseStatus.CONTINUE;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_0;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;
import static io.netty.util.internal.ObjectUtil.checkNotNull;

/** @author galudisu */
@Slf4j
public class Http1ServerHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
  private final String establishApproach;

  public Http1ServerHandler(String establishApproach) {
    this.establishApproach = checkNotNull(establishApproach, "establishApproach");
  }

  @Override
  public void channelReadComplete(ChannelHandlerContext ctx) {
    ctx.flush();
  }

  @Override
  protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) {
    if (HttpUtil.is100ContinueExpected(req)) {
      ctx.write(new DefaultFullHttpResponse(HTTP_1_1, CONTINUE));
    }
    boolean keepAlive = HttpUtil.isKeepAlive(req);
    ByteBuf content = ctx.alloc().buffer();
    content.writeBytes(Http2ServerHandler.RESPONSE_BYTES.duplicate());
    ByteBufUtil.writeAscii(
        content, " - via " + req.protocolVersion() + " (" + establishApproach + ")");
    FullHttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, OK, content);
    response.headers().set(CONTENT_TYPE, "text/plain; charset=UTF-8");
    response.headers().setInt(CONTENT_LENGTH, response.content().readableBytes());

    if (keepAlive) {
      if (req.protocolVersion().equals(HTTP_1_0)) {
        response.headers().set(CONNECTION, KEEP_ALIVE);
      }
      ctx.write(response);
    } else {
      // Tell the client we're going to close the connection.
      response.headers().set(CONNECTION, CLOSE);
      ctx.write(response).addListener(ChannelFutureListener.CLOSE);
    }
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
    log.debug("http1 server exception caught", cause);
    ctx.close();
  }
}
