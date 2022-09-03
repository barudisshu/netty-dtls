package io.netty.util.internal.jsse;

import io.netty.channel.ChannelHandler;
import io.netty.util.internal.dtls.adapter.DtlsEngine;
import io.netty.util.internal.dtls.adapter.JdkDtlsEngineAdapter;
import io.netty.util.internal.dtls.jsse.HandshakeDTLSHandler;
import io.netty.util.internal.test.AbstractMultiplexingDTLSTest;

import javax.net.ssl.*;
import java.security.SecureRandom;
import java.util.function.Supplier;

public class MultiplexingJsseDTLSTest extends AbstractMultiplexingDTLSTest {

  @Override
  protected ChannelHandler getMultiplexingHandler(
      KeyManagerFactory kmf, TrustManagerFactory tmf, SSLParameters parameters) throws Exception {

    SSLContext instance = SSLContext.getInstance("DTLSv1.2");

    instance.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

    Supplier<DtlsEngine> sslEngineSupplier =
        () -> {
          SSLEngine engine = instance.createSSLEngine();
          engine.setSSLParameters(parameters);
          return new JdkDtlsEngineAdapter(engine);
        };
    return new HandshakeDTLSHandler(sslEngineSupplier);
  }
}
