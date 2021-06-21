package io.netty.util.internal.cert.bctls.api;

/**
 * This interface provides constants used to interact with the Security Domain Manager managed
 * keystores and truststores.
 *
 * <p>Key stores and trust stores are accessed by name using property values of the form <code>
 * ${name}</code>. These values will be replaced by a file path, or a password, as appropriate.
 *
 * <p>To tell the configuration plugin which property keys require replacement the configuration
 * must contain one or more of the following properties:
 */
public interface SecurityDomainConfiguration {

  /**
   * This key maps to one or more keys in the configuration that should be transformed into key
   * store locations
   */
  String KEYSTORE_LOCATION = ".io.netty.util.internal.cert.keystore.location";
  /**
   * This key maps to one or more keys in the configuration that should be transformed into the type
   * of the key store
   */
  String KEYSTORE_TYPE = ".io.netty.util.internal.cert.keystore.type";
  /**
   * This key maps to one or more keys in the configuration that should be transformed into key
   * store passwords
   */
  String KEYSTORE_PW = ".io.netty.util.internal.cert.keystore.pw";
  /**
   * This key maps to one or more keys in the configuration that should be transformed into the
   * alias of the private key stored in the key store.
   */
  String KEYSTORE_ALIAS = ".io.netty.util.internal.cert.keystore.alias";
  /**
   * This key maps to one or more keys in the configuration that should be transformed into trust
   * store locations
   */
  String TRUSTSTORE_LOCATION = ".io.netty.util.internal.cert.truststore.location";
  /**
   * This key maps to one or more keys in the configuration that should be transformed into the type
   * of the trust store
   */
  String TRUSTSTORE_TYPE = ".io.netty.util.internal.cert.truststore.type";
  /**
   * This key maps to one or more keys in the configuration that should be transformed into trust
   * store passwords
   */
  String TRUSTSTORE_PW = ".io.netty.util.internal.cert.truststore.pw";
}
