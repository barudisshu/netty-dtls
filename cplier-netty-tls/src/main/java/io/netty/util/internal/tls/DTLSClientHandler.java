package io.netty.util.internal.tls;

import io.netty.channel.Channel;
import io.netty.util.concurrent.Future;

import java.net.SocketAddress;

/**
 * This interface represents a DTLS Handler which is capable of being a client or server, and that
 * can maintain a separate DTLS session per address that it communicates with.
 */
public interface DTLSClientHandler extends DTLSHandler {

  /**
   * Begin a handshake with the supplied remote address.
   *
   * <p>Note that a handshake will be implicitly started if the channel is connected to a remote
   * peer.
   *
   * @param socketAddress The address to handshake with
   * @return Either:
   *     <ul>
   *       <li>A Future representing the state of the initial handshake
   *       <li>A failed Future if the handshake has already started with a different address
   *     </ul>
   */
  public Future<Channel> handshake(SocketAddress socketAddress);
}
