package info.galudisu.http2_client;

import info.galudisu.Hightlight;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http2.HttpConversionUtil;
import io.netty.util.CharsetUtil;
import io.netty.util.internal.PlatformDependent;
import lombok.extern.slf4j.Slf4j;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Process {@link FullHttpResponse} translated from HTTP/2 frames
 *
 * @author Galudisu
 */
@Slf4j
public class HttpResponseHandler extends SimpleChannelInboundHandler<FullHttpResponse> {

  private final Map<Integer, MapValues> streamIdMap;

  public HttpResponseHandler() {
    this.streamIdMap = PlatformDependent.newConcurrentHashMap();
  }

  /**
   * Create an association between an anticipated response stream id and a {@link ChannelPromise}
   *
   * @param streamId The stream for which a response is expected
   * @param writeFuture A future that represent the request write operation
   * @param promise The promise object that will be used to wait/notify events
   * @return The previous object associated with {@code streamId}
   * @see HttpResponseHandler#awaitResponses(long, TimeUnit)
   */
  public MapValues put(int streamId, ChannelFuture writeFuture, ChannelPromise promise) {
    return streamIdMap.put(streamId, new MapValues(writeFuture, promise));
  }

  /**
   * Wait (sequentially) for a time duration for each anticipated response
   *
   * @param timeout Value of time to wait for each response
   * @param unit Units associated with {@code timeout}
   * @see HttpResponseHandler#put(int, ChannelFuture, ChannelPromise)
   */
  public String awaitResponses(long timeout, TimeUnit unit) {
    Iterator<Map.Entry<Integer, MapValues>> itr = streamIdMap.entrySet().iterator();
    String response = null;
    while (itr.hasNext()) {
      Map.Entry<Integer, MapValues> entry = itr.next();
      ChannelFuture writeFuture = entry.getValue().getWriteFuture();
      if (!writeFuture.awaitUninterruptibly(timeout, unit)) {
        throw new IllegalStateException(
            "Timed out waiting to write for stream id " + entry.getKey());
      }
      if (!writeFuture.isSuccess()) {
        throw new ChannelException(writeFuture.cause());
      }
      ChannelPromise promise = entry.getValue().getPromise();
      if (!promise.awaitUninterruptibly(timeout, unit)) {
        throw new IllegalStateException(
            "Timed out waiting for response on stream id " + entry.getKey());
      }
      if (!promise.isSuccess()) {
        throw new ChannelException(promise.cause());
      }
      log.debug("---Stream id: {} received---", entry.getKey());
      response = entry.getValue().getResponse();
      itr.remove();
    }
    return response;
  }

  @Override
  protected void channelRead0(ChannelHandlerContext ctx, FullHttpResponse msg) {
    Integer streamId =
        msg.headers().getInt(HttpConversionUtil.ExtensionHeaderNames.STREAM_ID.text());
    if (streamId == null) {
      log.error("HttpResponseHandler unexpected message received: {}", msg);
      return;
    }

    MapValues value = streamIdMap.get(streamId);
    if (value == null) {
      log.error("Message received for unknown stream id {}", streamId);
    } else {
      // Do stuff with the message (for now just print it)
      ByteBuf content = msg.content();
      if (content.isReadable()) { // NOSONAR
        int contentLength = content.readableBytes();
        var arr = new byte[contentLength];
        content.readBytes(arr);
        var response = new String(arr, 0, contentLength, CharsetUtil.UTF_8);
        log.debug(
            "\n{}--- TCP: Response from Sever ---{}\n{}{}{}\n",
            Hightlight.GREEN,
            Hightlight.RESET,
            Hightlight.YELLOW,
            response,
            Hightlight.RESET);
        value.setResponse(response);
      }
      value.getPromise().setSuccess();
    }
  }

  public static class MapValues {
    ChannelFuture writeFuture;
    ChannelPromise promise;
    String response;

    public String getResponse() {
      return response;
    }

    public void setResponse(String response) {
      this.response = response;
    }

    public MapValues(ChannelFuture writeFuture2, ChannelPromise promise2) {
      this.writeFuture = writeFuture2;
      this.promise = promise2;
    }

    public ChannelFuture getWriteFuture() {
      return writeFuture;
    }

    public ChannelPromise getPromise() {
      return promise;
    }
  }
}
