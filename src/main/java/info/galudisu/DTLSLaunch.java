package info.galudisu;

import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import java.io.IOException;

import static io.netty.util.internal.resources.openssl.SSLContextFactory.generateDTLSContext;

/** @author Galudisu */
@Slf4j
public final class DTLSLaunch implements Dispatch {

  private SSLContext getDTLSContext() {
    SSLContext sslCtx = null;
    try {
      sslCtx =
          generateDTLSContext(
              getPath("openssl/ca.crt"),
              getPath("openssl/server.crt"),
              getPath("openssl/pkcs8_server.key"),
              "server");
    } catch (IOException e) {
      log.debug("rollback to udp");
    }

    return sslCtx;
  }
}
