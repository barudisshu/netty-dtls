package info.galudisu.http2_server;

import io.netty.handler.codec.http2.*;

import static io.netty.handler.logging.LogLevel.DEBUG;

/** @author galudisu */
public class Http2ServerHandlerBuilder
    extends AbstractHttp2ConnectionHandlerBuilder<Http2ServerHandler, Http2ServerHandlerBuilder> {

  private static final Http2FrameLogger logger =
      new Http2FrameLogger(DEBUG, Http2ServerHandler.class);

  public Http2ServerHandlerBuilder() {
    frameLogger(logger);
  }

  @Override
  public Http2ServerHandler build() {
    return super.build();
  }

  @Override
  protected Http2ServerHandler build(
      Http2ConnectionDecoder decoder, Http2ConnectionEncoder encoder, Http2Settings http2Settings) {
    Http2ServerHandler handler = new Http2ServerHandler(decoder, encoder, http2Settings);
    frameListener(handler);
    return handler;
  }
}
