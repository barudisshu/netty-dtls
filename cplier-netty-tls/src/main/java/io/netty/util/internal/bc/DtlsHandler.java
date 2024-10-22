package io.netty.util.internal.bc;

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.socket.DatagramPacket;
import io.netty.util.internal.resources.thread.LocalThreadFactory;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.tls.DTLSTransport;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public abstract class DtlsHandler extends ChannelDuplexHandler {

  public static class ChannelContext {
    public final ChannelHandlerContext ctx;
    public final ChannelPromise promise;

    public ChannelContext(ChannelHandlerContext ctx, ChannelPromise promise) {
      super();
      this.ctx = ctx;
      this.promise = promise;
    }
  }

  private final LinkedBlockingQueue<ChannelContext> writeCtxQueue = new LinkedBlockingQueue<>();

  private final ExecutorService executor =
      Executors.newSingleThreadExecutor(
          new LocalThreadFactory(true, new AtomicInteger(), "DTLS-TRANSPORT"));

  protected final DtlsHandlerTransport rawTransport = new DtlsHandlerTransport();
  private final DtlsEngine engine = new DtlsEngine(rawTransport);

  @Override
  public void channelActive(final ChannelHandlerContext ctx) throws Exception {
    super.channelActive(ctx);
    rawTransport.setChannel(ctx.channel());
    executor.submit(
        () -> {
          try {
            log.debug(getName() + " init start ");

            final DTLSTransport encTransport = getDtlsTransport();
            log.debug("handshake finish");
            engine.initialize(encTransport);
            log.debug(getName() + " init end ");
          } catch (IOException | ExecutionException e) {
            log.error("handshake fail", e);
          } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
          }
        });
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object obj) throws Exception {
    if (obj instanceof DatagramPacket) {
      DatagramPacket msg = (DatagramPacket) obj;
      log.trace(getName() + " channelRead ");

      // send packet to underlying transport for consumption
      ArrayList<DatagramPacket> packets = engine.read(msg);
      for (DatagramPacket packet : packets) {
        super.channelRead(ctx, packet);
      }
    } else {
      super.channelRead(ctx, obj);
    }
  }

  @Override
  public void write(ChannelHandlerContext ctx, Object obj, ChannelPromise promise)
      throws Exception {
    if (obj instanceof DatagramPacket) {
      // this is the unencryped data written by the app
      DatagramPacket msg = (DatagramPacket) obj;

      log.trace(getName() + " write " + msg);

      // flush the queue when channel initialized
      if (engine.isInitialized()) {
        // assume messages are one-to-one between raw and encrypted
        writeCtxQueue.add(new ChannelContext(ctx, promise));
      }
      engine.write(msg);
    } else if (obj instanceof DtlsPacket) {
      // used to passthrough the data for handshake packets

      // this is the underlying traffic written by this handler
      DtlsPacket msg = (DtlsPacket) obj;

      ChannelContext context = writeCtxQueue.poll();
      if (context != null) {
        super.write(context.ctx, msg.packet, context.promise);
      } else {
        super.write(ctx, msg.packet, promise);
      }
    } else {
      super.write(ctx, obj, promise);
    }
  }

  protected String getName() {
    return this.getClass().toString();
  }

  protected abstract DTLSTransport getDtlsTransport() throws IOException;
}
