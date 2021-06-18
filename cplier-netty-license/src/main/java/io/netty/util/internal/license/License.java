package io.netty.util.internal.license;

import java.io.*;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class License {
  public static final String COUNT_KEY = "count";
  public static final String EMAIL_KEY = "email";
  public static final String ERROR_KEY = "error";
  public static final String EXPIRE_KEY = "expires";
  public static final String FLAGS_KEY = "flags";
  public static final String NOTICE_KEY = "notice";
  public static final String SIG_KEY = "sig";
  public static final String URL_KEY = "url";
  public static final String VERSION_KEY = "version";
  public static final String KEY_SEP = ";";
  public static final String ALOGRITHM = "SHA1withDSA";

  private static final String ASCII = "ASCII";
  private static final String licFile =
      System.getProperty("posh.home", System.getProperty("user.dir")) + "/etc/license.ini";
  private static final String licURL =
      System.getProperty("posh.updateURL", "mailto:com.paremus.license@paremus.com");

  private static final AtomicBoolean reportedMissingLicense = new AtomicBoolean();
  private static final Set<String> reportedMissingFeatures =
      Collections.synchronizedSet(new HashSet<>());

  // we don't want hackers substituting their own public keys,
  // so embed cert here, rather than reading from file.
  // generated using: keytool -export -rfc -keystore licStore -alias licSign
  private static final String CERT =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIIC9TCCArMCBEYvvEswCwYHKoZIzjgEAwUAMGAxCzAJBgNVBAYTAlVLMQswCQYDVQQIEwJVSzEP\n"
          + "MA0GA1UEBxMGTG9uZG9uMRAwDgYDVQQKEwdQYXJlbXVzMQwwCgYDVQQLEwNEU0YxEzARBgNVBAMT\n"
          + "CkluZmluaWZsb3cwHhcNMDcwNDI1MjAzODM1WhcNMTAwMTE4MjAzODM1WjBgMQswCQYDVQQGEwJV\n"
          + "SzELMAkGA1UECBMCVUsxDzANBgNVBAcTBkxvbmRvbjEQMA4GA1UEChMHUGFyZW11czEMMAoGA1UE\n"
          + "CxMDRFNGMRMwEQYDVQQDEwpJbmZpbmlmbG93MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4Ed\n"
          + "dRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/Jm\n"
          + "YLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv\n"
          + "8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6\n"
          + "OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuz\n"
          + "pnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGB\n"
          + "AKn9AcUYNh/vV4ExfN3jHWNZINbyzBKWPj+hvRA7FMDJ1Kt0wDd96tobXHTrhXE9XkRfiHGGNtBC\n"
          + "nvKKUGQ1ieDL+aQQ/0skFcu5/qPvXvIetlnLyNslFJl9eDs010X+OWJsOSw8PZcLex8HgsBot/wL\n"
          + "BWJ1ihjBy8vzCywuzUVtMAsGByqGSM44BAMFAAMvADAsAhRP2gp7bE2ClJKwGka6AWcj5s0LqgIU\n"
          + "UqlNmekYJx5asmYknvkDtJ2PJj0=\n"
          + "-----END CERTIFICATE-----\n";

  private static final PublicKey pubKey;

  static {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      Certificate cert = cf.generateCertificate(new ByteArrayInputStream(CERT.getBytes(ASCII)));
      pubKey = cert.getPublicKey();
    } catch (Exception e) {
      notice(
          null,
          "LICENSE ERROR - com.paremus.license has been corrupted",
          "Error: " + e.getMessage());
      throw new RuntimeException("Failed to read embedded certificate, file is corrupted", e);
    }
  }

  /**
   * require a com.paremus.license for the named feature.
   *
   * @param name the name of the feature
   * @param version the version required, or null to skip version checking
   */
  public static void requireFeature(String name, String version) {
    License lic;
    try {
      lic = new License(licFile);
    } catch (LicenseError le) {
      if (!reportedMissingLicense.getAndSet(true)) {
        missingLicense(le);
      }
      return;
    }
    Map<String, String> attrs = new HashMap<String, String>();
    if (version != null && version.length() > 0) attrs.put(VERSION_KEY, version);
    try {
      lic.requireFeature(name, attrs);
    } catch (LicenseError le) {
      if (reportedMissingFeatures.add(name)) {
        notice(
            null,
            "LICENSE WARNING - Failed to validate feature " + name + " " + version,
            "File: " + licFile,
            "Error: " + le.getMessage());
      }
    }
  }

  private Properties licenseProps;
  private TreeSet<String> keys = new TreeSet<String>();
  private TreeSet<String> features = new TreeSet<String>();

  public License(String file) throws LicenseError {
    licenseProps = new Properties();
    FileInputStream stream;
    try {
      stream = new FileInputStream(file);
      licenseProps.load(stream);
      stream.close();
    } catch (FileNotFoundException e) {
      throw new LicenseError("License file doesn't exist", e);
    } catch (IOException e) {
      throw new LicenseError("Error reading com.paremus.license file", e);
    }

    for (Object k : licenseProps.keySet()) {
      String key = (String) k;
      keys.add(key);
      int index = key.indexOf(KEY_SEP);
      if (index > 0) features.add(key.substring(0, index));
    }
  }

  public Set<String> getFeatures() {
    return features;
  }

  public Map<String, String> getFeature(String name) throws LicenseError {
    String sig = licenseProps.getProperty(name + KEY_SEP + SIG_KEY);

    if (sig == null) throw new LicenseError("no com.paremus.license for feature: " + name);

    try {
      Signature dsa = Signature.getInstance(ALOGRITHM);
      dsa.initVerify(pubKey);
      dsa.update(getData(name));

      if (!dsa.verify(decode(sig)))
        throw new LicenseError("signature failed verification for feature: " + name);
    } catch (NumberFormatException e) {
      // hex signature -- odd length or non-hex character
      throw new LicenseError("signature format error for feature: " + name, e);
    } catch (SignatureException e) {
      // hex signature -- doesn't represent valid signature
      throw new LicenseError("signature not valid for feature: " + name, e);
    } catch (Exception e) {
      throw new LicenseError("internal error verifying signature for feature: " + name, e);
    }

    return getConfig(name);
  }

  // get data to which signature applies
  private byte[] getData(String name) throws LicenseError {
    try {
      return getConfig(name).toString().getBytes(ASCII);
    } catch (UnsupportedEncodingException e) {
      throw new LicenseError("internal error", e);
    }
  }

  private Map<String, String> getConfig(String name) {
    // Note: need TreeMap to ensure getBytes returns identical result on all platforms.
    Map<String, String> config = new TreeMap<String, String>();

    for (String key : keys) {
      if (key.startsWith(name + KEY_SEP)) {
        String k = key.substring(name.length() + 1);
        if (!k.equals(SIG_KEY)) config.put(k, licenseProps.getProperty(key).trim());
      }
    }

    return config;
  }

  private static byte[] decode(String s) {
    if (s.length() % 2 != 0) throw new NumberFormatException("odd hex string");

    byte[] bytes = new byte[s.length() / 2];

    for (int i = 0; i < bytes.length; ++i) {
      int i2 = i * 2;
      String b1 = s.substring(i2, ++i2);
      String b2 = s.substring(i2, ++i2);
      bytes[i] = (byte) (Byte.parseByte(b1, 16) << 4);
      bytes[i] += Byte.parseByte(b2, 16);
    }

    return bytes;
  }

  private static void err(String msg) {
    System.err.println(msg);
  }

  /*
   * fatal - give nice message explaining the problem.
   */
  private static void missingLicense(LicenseError e) {
    notice(
        null,
        "LICENSE WARNING - missing or corrupt com.paremus.license",
        "File: " + licFile,
        "Error: " + e.getMessage());
  }

  private static void notice(String url, String... args) {
    String stars = "**********************************************************************";
    String star3 = "**  ";

    if (url == null) url = licURL;

    err("");
    err(stars);
    for (String msg : args) err(star3 + msg);

    err(star3);
    err(star3 + "Paremus components are released under the Fair Source License, and can");
    err(star3 + "be used freely up to the use limitation. If you exceed this level of");
    err(star3 + "usage then you must obtain a commercial license.");
    err(star3);
    err(star3 + "Please consider obtaining a new com.paremus.license from " + url);
    err(stars);
    err("");
  }

  /**
   * require a com.paremus.license for the named feature.
   *
   * @param name the name of the feature
   * @param attrs the attributes required (e.g. version)
   * @return The map of feature attributes
   * @throws LicenseError if the license cannot be validated for this feature
   */
  public Map<String, String> requireFeature(String name, Map<String, String> attrs)
      throws LicenseError {
    Map<String, String> feature = getFeature(name);

    Date expiry = getExpiry(feature);
    long remain = expiry.getTime() - System.currentTimeMillis();
    long days = remain / 1000 / 60 / 60 / 24;
    String range = feature.get(VERSION_KEY);
    String version = attrs.get(VERSION_KEY);

    if (remain < 0) {
      throw new LicenseError(
          "com.paremus.license has expired, License for feature '"
              + name
              + "' expired on "
              + expiry);
    } else if (range != null && version != null && !versionInRange(version, range)) {
      throw new LicenseError(
          "Feature '"
              + name
              + "' is not licensed at version '"
              + version
              + "'. Acceptable version range is '"
              + range
              + "'");
    } else if (days < 8) {
      if (reportedMissingFeatures.add(name)) {
        String s = (days == 1) ? " day" : " days";
        notice(
            feature.get(URL_KEY),
            "LICENSE WARNING: '" + name + "' com.paremus.license expires in " + days + s,
            expiry.toString());
      }
    }

    String notice = feature.get(NOTICE_KEY);

    if (notice != null) {
      String email = feature.get(EMAIL_KEY);
      String issued = (email == null ? "nobody" : email);
      String expires = (expiry == null ? "never" : expiry.toString());
      feature.put(NOTICE_KEY, notice.replace("{expires}", expires).replace("{issued}", issued));
    }

    return feature;
  }

  private boolean versionInRange(String version, String range) {
    if ((range.startsWith("[")) || (range.startsWith("("))) {
      int len = range.length() - 1;
      char floor = range.charAt(0);
      char ceiling = range.charAt(len);
      String[] rv = range.substring(1, len).split("\\s*,\\s*");
      int f = versionCompare(version, rv[0]);
      int c = versionCompare(version, rv[1]);

      return (floor == '[' ? f >= 0 : f > 0) && (ceiling == ']' ? c <= 0 : c < 0);
    }

    return versionCompare(version, range) >= 0;
  }

  /** simple OSGi version compare. */
  private int versionCompare(String v1, String v2) {
    String[] s1 = v1.split("[.]", 4);
    String[] s2 = v2.split("[.]", 4);
    String q1 = s1.length == 4 ? s1[3] : "";
    String q2 = s2.length == 4 ? s2[3] : "";
    int i1[] = new int[3];
    int i2[] = new int[3];

    for (int i = 0; i < 3; ++i) {
      i1[i] = s1.length < i + 1 ? 0 : Integer.parseInt(s1[i]);
      i2[i] = s2.length < i + 1 ? 0 : Integer.parseInt(s2[i]);
    }

    for (int i = 0; i < 3; ++i) {
      if (i1[i] > i2[i]) return 1;
      if (i1[i] < i2[i]) return -1;
    }

    return q1.compareTo(q2);
  }

  /**
   * get expiry date, or null if feature doesn't expire.
   *
   * @return
   */
  private static Date getExpiry(Map<String, String> feature) throws LicenseError {
    SimpleDateFormat format = new SimpleDateFormat("yy-MM-dd");
    String expires = feature.get(EXPIRE_KEY);

    if (expires != null) {
      try {
        long millis = format.parse(expires).getTime();
        millis += 24 * 60 * 60 * 1000;
        millis -= 1000;
        return new Date(millis);
      } catch (ParseException e) {
        // we've got a verified feature with a bad expiry date
        throw new LicenseError("illegal expiry date: " + expires);
      }
    } else {
      return new Date(Long.MAX_VALUE);
    }
  }
}
