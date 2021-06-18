package info.galudisu.http2_server;

import info.galudisu.Hightlight;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http2.*;
import io.netty.util.CharsetUtil;
import lombok.extern.slf4j.Slf4j;

import static io.netty.buffer.Unpooled.copiedBuffer;
import static io.netty.buffer.Unpooled.unreleasableBuffer;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http2.Http2CodecUtil.getEmbeddedHttp2Exception;

/** @author galudisu */
@Slf4j
public class Http2ServerHandler extends Http2ConnectionHandler implements Http2FrameListener {
  static final ByteBuf RESPONSE_BYTES = unreleasableBuffer(copiedBuffer("OK", CharsetUtil.UTF_8));

  public Http2ServerHandler(
      Http2ConnectionDecoder decoder,
      Http2ConnectionEncoder encoder,
      Http2Settings initialSettings) {
    super(decoder, encoder, initialSettings);
  }

  private static Http2Headers http1HeadersToHttp2Headers(FullHttpRequest request) {
    CharSequence host = request.headers().get(HttpHeaderNames.HOST);
    var http2Headers =
        new DefaultHttp2Headers()
            .method(HttpMethod.GET.asciiName())
            .path(request.uri())
            .scheme(HttpScheme.HTTP.name());
    if (host != null) {
      http2Headers.authority(host);
    }
    return http2Headers;
  }

  @Override
  public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
    if (evt instanceof HttpServerUpgradeHandler.UpgradeEvent) {
      var upgradeEvent =
          (HttpServerUpgradeHandler.UpgradeEvent) evt;
      onHeadersRead(ctx, 1, http1HeadersToHttp2Headers(upgradeEvent.upgradeRequest()), 0, true);
    }
    super.userEventTriggered(ctx, evt);
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
    if (getEmbeddedHttp2Exception(cause) != null) {
      super.exceptionCaught(ctx, cause);
    } else {
      ctx.channel().close();
    }
  }

  @Override
  public int onDataRead(
      ChannelHandlerContext ctx, int streamId, ByteBuf data, int padding, boolean endOfStream) {
    int processed = data.readableBytes() + padding;
    if (endOfStream) {
      log.debug(
          "\n{}--- TCP: Mock Server receiving request ---{}\n{}{}{}\n",
          Hightlight.GREEN,
          Hightlight.RESET,
          Hightlight.CYAN,
          data.toString(CharsetUtil.UTF_8),
          Hightlight.RESET);
      sendResponse(ctx, streamId, data.retain());
    }
    return processed;
  }

  @Override
  public void onHeadersRead(
      ChannelHandlerContext ctx,
      int streamId,
      Http2Headers headers,
      int padding,
      boolean endOfStream) {
    if (endOfStream) {
      ByteBuf content = ctx.alloc().buffer();
      content.writeBytes(RESPONSE_BYTES.duplicate());
      ByteBufUtil.writeAscii(content, " - via HTTP/2");
      sendResponse(ctx, streamId, content);
    }
  }

  @Override
  public void onHeadersRead(
      ChannelHandlerContext ctx,
      int streamId,
      Http2Headers headers,
      int streamDependency,
      short weight,
      boolean exclusive,
      int padding,
      boolean endOfStream) {
    onHeadersRead(ctx, streamId, headers, padding, endOfStream);
  }

  @Override
  public void onPriorityRead(
      ChannelHandlerContext channelHandlerContext, int i, int i1, short i2, boolean b) {
    // NOSONAR
  }

  @Override
  public void onRstStreamRead(ChannelHandlerContext channelHandlerContext, int i, long l) {
    // NOSONAR
  }

  @Override
  public void onSettingsAckRead(ChannelHandlerContext channelHandlerContext) {
    // NOSONAR
  }

  @Override
  public void onSettingsRead(
      ChannelHandlerContext channelHandlerContext, Http2Settings http2Settings) {
    // NOSONAR
  }

  @Override
  public void onPingRead(ChannelHandlerContext channelHandlerContext, long l) {
    // NOSONAR
  }

  @Override
  public void onPingAckRead(ChannelHandlerContext channelHandlerContext, long l) {
    // NOSONAR
  }

  @Override
  public void onPushPromiseRead(
      ChannelHandlerContext channelHandlerContext,
      int i,
      int i1,
      Http2Headers http2Headers,
      int i2) {
    // NOSONAR
  }

  @Override
  public void onGoAwayRead(
      ChannelHandlerContext channelHandlerContext, int i, long l, ByteBuf byteBuf) {
    // NOSONAR
  }

  @Override
  public void onWindowUpdateRead(ChannelHandlerContext channelHandlerContext, int i, int i1) {
    // NOSONAR
  }

  @Override
  public void onUnknownFrame(
      ChannelHandlerContext channelHandlerContext,
      byte b,
      int i,
      Http2Flags http2Flags,
      ByteBuf byteBuf) {
    // NOSONAR
  }

  private void sendResponse(ChannelHandlerContext ctx, int streamId, ByteBuf payload) {
    // Send a frame for the response status
    Http2Headers headers = new DefaultHttp2Headers().status(OK.codeAsText());
    encoder().writeHeaders(ctx, streamId, headers, 0, false, ctx.newPromise());
    encoder().writeData(ctx, streamId, payload, 0, true, ctx.newPromise());
  }
}
