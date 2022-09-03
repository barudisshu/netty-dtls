package info.galudisu.http2_server;

import io.netty.handler.codec.http.HttpServerUpgradeHandler;
import io.netty.handler.codec.http2.Http2CodecUtil;
import io.netty.handler.codec.http2.Http2ServerUpgradeCodec;
import io.netty.util.AsciiString;

/** @author galudisu */
public class HttpUpgradeCodecFactory implements HttpServerUpgradeHandler.UpgradeCodecFactory {

  @Override
  public HttpServerUpgradeHandler.UpgradeCodec newUpgradeCodec(CharSequence protocol) {
    if (AsciiString.contentEquals(Http2CodecUtil.HTTP_UPGRADE_PROTOCOL_NAME, protocol)) {
      return new Http2ServerUpgradeCodec(new Http2ServerHandlerBuilder().build());
    } else {
      return null;
    }
  }
}
