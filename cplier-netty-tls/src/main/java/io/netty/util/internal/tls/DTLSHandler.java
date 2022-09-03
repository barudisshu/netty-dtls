package io.netty.util.internal.tls;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.util.concurrent.Future;

import java.net.SocketAddress;

/**
 * This interface represents a DTLS Handler which is capable of being a client or server, and that
 * can maintain a separate DTLS session per address that it communicates with.
 */
public interface DTLSHandler extends ChannelHandler {

  /**
   * Get the handshake future for this handler
   *
   * @return a future representing the state of the current handshake, or null if no handshake or
   *     connection is ongoing
   */
  Future<Channel> handshakeFuture();

  /**
   * Get the close future for this handler
   *
   * @return a future representing the state of the current connection, or null if no connection is
   *     ongoing
   */
  Future<Void> closeFuture();

  /**
   * Get the address of the remote peer which this Handler is for
   *
   * @return the remote address, or null if this hander is not yet connected
   */
  SocketAddress getRemotePeerAddress();
}
