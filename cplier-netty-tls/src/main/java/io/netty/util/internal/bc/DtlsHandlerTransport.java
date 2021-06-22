package io.netty.util.internal.bc;

import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.socket.DatagramPacket;
import org.bouncycastle.tls.DatagramTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

class DtlsHandlerTransport implements DatagramTransport {

  private static final Logger log = LoggerFactory.getLogger(DtlsHandlerTransport.class);

  public static final int RECV_BUFFER_SIZE = 65536;
  public static final int SEND_BUFFER_SIZE = 65536;

  private final LinkedBlockingQueue<DatagramPacket> readQueue = new LinkedBlockingQueue<>();

  private Channel channel = null;
  private InetSocketAddress remoteAddress = null;

  @Override
  public void send(byte[] buf, int off, int len) throws IOException {
    log.trace(" send {} bytes", len);
    var packet = new DatagramPacket(Unpooled.copiedBuffer(buf, off, len), remoteAddress);
    channel.writeAndFlush(new DtlsPacket(packet));
  }

  @Override
  public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
    log.trace(" receive ");
    try {
      DatagramPacket packet = readQueue.poll(waitMillis, TimeUnit.MILLISECONDS);
      log.trace(" receive polled: {}", packet);
      if (packet != null) {
        var byteBuf = packet.content();
        int bytesToRead = Math.min(byteBuf.readableBytes(), len);
        byteBuf.readBytes(buf, off, bytesToRead);
        byteBuf.release();
        return bytesToRead;
      } else {
        return 0;
      }
    } catch (InterruptedException e) {
      log.error("dtls interrupted", e);
      Thread.currentThread().interrupt();
      return 0;
    }
  }

  @Override
  public int getSendLimit() throws IOException {
    return SEND_BUFFER_SIZE;
  }

  @Override
  public int getReceiveLimit() throws IOException {
    return RECV_BUFFER_SIZE;
  }

  @Override
  public void close() throws IOException {
    channel.close();
  }

  public void enqueue(DatagramPacket msg) {
    readQueue.add(msg);
  }

  public boolean hasPackets() {
    return !readQueue.isEmpty();
  }

  public InetSocketAddress getRemoteAddress() {
    return remoteAddress;
  }

  public void setRemoteAddress(InetSocketAddress address) {
    this.remoteAddress = address;
  }

  public void setChannel(Channel channel) {
    this.channel = channel;
  }
}
