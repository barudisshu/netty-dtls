package io.netty.util.internal.cert.jsse;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.InputStream;

/**
 * Only support RSA. now!!
 *
 * @author galudisu
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SslStream {

  private InputStream caPath;
  private InputStream certificatePath;
  private InputStream privateKeyPath;
}
