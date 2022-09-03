package io.netty.util.internal.cert.bctls.domain;

import io.netty.util.internal.cert.bctls.api.CertificateInfo;
import io.netty.util.internal.cert.bctls.domain.AbstractStoreManager.StoreInfo;
import org.apache.cxf.jaxrs.servlet.CXFNonSpringJaxrsServlet;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.ws.rs.*;
import javax.ws.rs.core.Response.Status;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;

import static java.time.Duration.ofHours;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class CertificateSigningRequestSubmitterTest {

  @TempDir java.nio.file.Path tempFolder;

  private final BouncyCastleProvider provider = new BouncyCastleProvider();
  private final SecureRandom secureRandom = new SecureRandom();

  private KeyPairManager keyPairManager;
  private CertificateGenerator certificateGenerator;
  private KeyStoreManager keyStoreManager;
  private TrustStoreManager trustStoreManager;

  private Server server;

  private int localPort;

  @BeforeEach
  void start() throws Exception {
    keyPairManager = new KeyPairManager(tempFolder, provider, secureRandom);
    certificateGenerator = new CertificateGenerator(provider, secureRandom);
    keyStoreManager = new KeyStoreManager(tempFolder, provider, secureRandom);
    trustStoreManager = new TrustStoreManager(tempFolder, provider, secureRandom);

    KeyPair keyPair = keyPairManager.newKeyPair("test");

    Certificate certificate =
        certificateGenerator.generateRootCertificate(keyPair, "localhost", ofHours(1));

    keyStoreManager.createKeyStore("test_store", keyPair, new Certificate[] {certificate});

    StoreInfo storeInfo = keyStoreManager.getStoreFor("test_store", "test_pid");

    server = new Server();

    HttpConfiguration https = new HttpConfiguration();
    https.addCustomizer(new SecureRequestCustomizer());
    SslContextFactory sslContextFactory = new SslContextFactory();
    sslContextFactory.setKeyStorePath(storeInfo.location);
    sslContextFactory.setKeyStorePassword(storeInfo.password);
    sslContextFactory.setKeyManagerPassword(storeInfo.password);
    ServerConnector sslConnector =
        new ServerConnector(
            server,
            new SslConnectionFactory(sslContextFactory, "http/1.1"),
            new HttpConnectionFactory(https));
    sslConnector.setPort(0);

    server.addConnector(sslConnector);

    CXFNonSpringJaxrsServlet servlet = new CXFNonSpringJaxrsServlet(new SigningResource());

    ServletHandler handler = new ServletHandler();
    handler.addServletWithMapping(new ServletHolder(servlet), "/*");
    server.setHandler(handler);

    server.start();

    localPort = sslConnector.getLocalPort();
  }

  @AfterEach
  void stop() throws Exception {
    server.stop();
    server.destroy();
  }

  public class SigningResource {

    @Path("sign")
    @POST
    @Consumes("text/plain")
    @Produces("text/plain")
    public String sign(@HeaderParam("One-Time-Token") String token, String body) {

      if (!"SECRET".equals(token)) {
        throw new WebApplicationException(Status.FORBIDDEN);
      }

      return certificateGenerator.signCertificate(
          keyStoreManager.getSignerInfo("test_store"), body);
    }
  }

  @Test
  void testSigning() throws MalformedURLException {
    CertificateSigningRequestSubmitter submitter =
        new CertificateSigningRequestSubmitter(trustStoreManager, secureRandom);

    URL url = new URL("https", "localhost", localPort, "/sign");

    KeyPair keyPair = keyPairManager.newKeyPair("to_sign");
    String signingRequest =
        certificateGenerator.generateCertificateSigningRequest(keyPair, "client_cert");

    String signedCertAndChain =
        submitter.issueCertificateSigningRequest(
            url, signingRequest, "SECRET", keyStoreManager.getCertificateChain("test_store"));

    keyStoreManager.createKeyStore("signed", keyPair, signedCertAndChain);

    CertificateInfo certificateInfo = keyStoreManager.getCertificateInfo("signed");

    assertEquals("client_cert", certificateInfo.getSubject());
  }
}
