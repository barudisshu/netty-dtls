package io.netty.util.internal.jsse;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.DatagramPacket;
import io.netty.util.concurrent.Future;
import io.netty.util.internal.dtls.adapter.JdkDtlsEngineAdapter;
import io.netty.util.internal.dtls.jsse.ClientDTLSHandler;
import io.netty.util.internal.dtls.jsse.ServerDTLSHandler;
import io.netty.util.internal.test.AbstractDTLSTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class JsseDTLSTest extends AbstractDTLSTest {

  @Test
  void testECCertificate() throws Exception {
    setupEC();
    sayHello();
  }

  @Test
  void testRSACertificate() throws Exception {
    setupRSA();
    sayHello();
  }

  private void sayHello() throws Exception {

    udpBootstrap.handler(new ChannelInitializer<>() {
      @Override
      protected void initChannel(Channel ch) throws Exception {
        SSLContext instance = SSLContext.getInstance("DTLSv1.2");
        instance.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLEngine engine = instance.createSSLEngine();
        engine.setUseClientMode(true);
        ch.pipeline().addFirst(new ClientDTLSHandler(new JdkDtlsEngineAdapter(engine)));
      }
    });

    Channel alice = udpBootstrap.bind(InetAddress.getLoopbackAddress(), 0).sync().channel();

    udpBootstrap.handler(new ChannelInitializer<>() {
      @Override
      protected void initChannel(Channel ch) throws Exception {
        SSLContext instance = SSLContext.getInstance("DTLSv1.2");
        instance.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLEngine engine = instance.createSSLEngine();
        engine.setUseClientMode(false);
        ch.pipeline().addFirst(new ServerDTLSHandler(new JdkDtlsEngineAdapter(engine)));
      }
    });

    Channel bob = udpBootstrap.bind(InetAddress.getLoopbackAddress(), 0).sync().channel();

    BlockingQueue<String> aliceMessages = new LinkedBlockingQueue<>();
    BlockingQueue<String> bobMessages = new LinkedBlockingQueue<>();

    alice.pipeline().addLast(new CapturingHandler(aliceMessages));
    bob.pipeline().addLast(new CapturingHandler(bobMessages));

    alice.connect(bob.localAddress()).sync();

    Future<Channel> handshakeFuture =
        alice.pipeline().get(ClientDTLSHandler.class).handshakeFuture();
    assertTrue(handshakeFuture.await(1000));
    handshakeFuture.get(0, TimeUnit.MILLISECONDS);

    handshakeFuture = bob.pipeline().get(ServerDTLSHandler.class).handshakeFuture();
    assertTrue(handshakeFuture.await(1000));
    handshakeFuture.get(0, TimeUnit.MILLISECONDS);

    ByteBuf buffer = Unpooled.buffer();
    buffer.writeCharSequence("Hello from Alice", UTF_8);
    assertTrue(
        alice
            .writeAndFlush(new DatagramPacket(buffer, (InetSocketAddress) bob.localAddress()))
            .await(2000));

    buffer = Unpooled.buffer();
    buffer.writeCharSequence("Hello from Bob", UTF_8);
    assertTrue(
        bob.writeAndFlush(new DatagramPacket(buffer, (InetSocketAddress) alice.localAddress()))
            .await(2000));

    assertEquals("Hello from Alice", bobMessages.poll(100, TimeUnit.MILLISECONDS));
    assertEquals("Hello from Bob", aliceMessages.poll(100, TimeUnit.MILLISECONDS));

    assertTrue(alice.close().await(1000));
    assertTrue(bob.close().await(1000));
  }
}
