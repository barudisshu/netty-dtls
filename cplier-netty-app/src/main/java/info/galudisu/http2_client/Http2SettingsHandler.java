package info.galudisu.http2_client;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http2.Http2Settings;

import java.util.concurrent.TimeUnit;

/**
 * Reads the first {@link Http2Settings} object and notifies a {@link ChannelPromise}
 *
 * @author galudisu
 */
public class Http2SettingsHandler extends SimpleChannelInboundHandler<Http2Settings> {

  private final ChannelPromise promise;

  public Http2SettingsHandler(ChannelPromise promise) {
    this.promise = promise;
  }

  public void awaitSettings(long timeout, TimeUnit unit) {
    if (!promise.awaitUninterruptibly(timeout, unit)) {
      throw new IllegalStateException("Timed out waiting for settings");
    }
  }

  @Override
  protected void channelRead0(ChannelHandlerContext ctx, Http2Settings msg) {
    promise.setSuccess();
    ctx.pipeline().remove(this);
  }
}
