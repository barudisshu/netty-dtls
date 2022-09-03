package io.netty.util.internal.test;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.util.ResourceLeakDetector;
import io.netty.util.ResourceLeakDetector.Level;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.UTF_8;

public abstract class AbstractDTLSTest {

  public static final class CapturingHandler extends ChannelInboundHandlerAdapter {

    private final BlockingQueue<String> readData;

    public CapturingHandler(BlockingQueue<String> readData) {
      this.readData = readData;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
      ByteBuf content = ((DatagramPacket) msg).content();
      readData.put(content.readCharSequence(content.readableBytes(), UTF_8).toString());
      content.release();
    }
  }

  private NioEventLoopGroup group;
  protected Bootstrap udpBootstrap;

  private static final char[] EC_KEYSTORE_PW = "36e1b16c586196ab".toCharArray();
  private static final char[] EC_TRUSTSTORE_PW = "f9f0a7084b8e28ff".toCharArray();
  protected SSLParameters parameters;
  protected KeyManagerFactory kmf;
  protected TrustManagerFactory tmf;

  @BeforeEach
  public void setup() {
    System.setProperty(
        "io.netty.customResourceLeakDetector", TestResourceLeakDetector.class.getName());

    ResourceLeakDetector.setLevel(Level.PARANOID);

    group = new NioEventLoopGroup();
    udpBootstrap = new Bootstrap();
    udpBootstrap.group(group).channel(NioDatagramChannel.class);
  }

  @AfterEach
  public void tearDown() throws Exception {
    group.shutdownGracefully(250, 1000, TimeUnit.MILLISECONDS).sync();
    TestResourceLeakDetector.assertNoLeaks();
  }

  protected void setupEC()
      throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
          UnrecoverableKeyException, KeyManagementException {
    setupSSL(
        "PKCS12",
        "/ec_test.keystore",
        EC_KEYSTORE_PW,
        "PKCS12",
        "/ec_test.truststore",
        EC_TRUSTSTORE_PW);
  }

  protected void setupRSA()
      throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
          UnrecoverableKeyException, KeyManagementException {
    setupSSL(
        "JKS",
        "/fabric.keystore",
        "paremus".toCharArray(),
        "JKS",
        "/fabric.truststore",
        "paremus".toCharArray());
  }

  private void setupSSL(
      String keystoreType,
      String keystorepath,
      char[] keystorePassword,
      String truststoreType,
      String truststorepath,
      char[] truststorePassword)
      throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
          UnrecoverableKeyException, KeyManagementException {
    KeyStore keyStore = KeyStore.getInstance(keystoreType);
    keyStore.load(getClass().getResourceAsStream(keystorepath), keystorePassword);

    KeyStore trustStore = KeyStore.getInstance(truststoreType);
    trustStore.load(getClass().getResourceAsStream(truststorepath), truststorePassword);

    kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keyStore, keystorePassword);

    tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(trustStore);

    SSLContext instance = SSLContext.getInstance("DTLSv1.2");
    instance.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
    parameters = instance.getDefaultSSLParameters();
    parameters.setNeedClientAuth(true);
  }
}
