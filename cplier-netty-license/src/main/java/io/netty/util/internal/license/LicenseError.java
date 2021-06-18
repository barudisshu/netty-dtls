package io.netty.util.internal.license;

public class LicenseError extends Exception {
  private static final long serialVersionUID = 1L;

  public LicenseError(String m) {
    super(m);
  }

  public LicenseError(String m, Throwable e) {
    super(m, e);
  }
}
