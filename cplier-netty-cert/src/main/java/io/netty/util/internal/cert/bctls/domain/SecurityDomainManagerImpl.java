package io.netty.util.internal.cert.bctls.domain;

import io.netty.util.internal.cert.bctls.api.CertificateInfo;
import io.netty.util.internal.cert.bctls.api.KeyPairInfo;
import io.netty.util.internal.cert.bctls.api.SecurityDomainManager;
import io.netty.util.internal.cert.bctls.domain.AbstractStoreManager.StoreInfo;
import io.netty.util.internal.cert.exception.SslException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.cm.*;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.util.converter.Converter;
import org.osgi.util.converter.TypeReference;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.time.Duration;
import java.util.*;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.netty.util.internal.cert.bctls.api.SecurityDomainConfiguration.*;
import static java.util.Collections.emptyList;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;
import static org.osgi.framework.Constants.SERVICE_PID;
import static org.osgi.service.component.annotations.ReferenceCardinality.OPTIONAL;
import static org.osgi.service.component.annotations.ReferencePolicy.DYNAMIC;
import static org.osgi.util.converter.Converters.standardConverter;

@Component(immediate = true, configurationPid = "io.netty.util.internal.cert.security.domain")
@Designate(ocd = Config.class)
public class SecurityDomainManagerImpl
    implements ConfigurationPlugin, ConfigurationListener, SecurityDomainManager {

  private static final TypeReference<List<String>> LIST_OF_STRINGS =
      new TypeReference<List<String>>() {};

  private static final String EXISTING_CONFIG_FILTER =
      "(|(" + KEYSTORE_LOCATION + "=*)(" + TRUSTSTORE_LOCATION + "=*))";
  private static final String PID_FILTER_TEMPLATE = "(service.pid=%s)";

  private final Converter converter = standardConverter();

  private final BouncyCastleProvider provider = new BouncyCastleProvider();
  private final SecureRandom secureRandom = new SecureRandom();

  private final Map<String, Set<String>> referencedKeyStores = new HashMap<>();
  private final Map<String, Set<String>> referencedTrustStores = new HashMap<>();

  private final Object lock = new Object();
  private int state = 0;

  private KeyStoreManager ksm;
  private TrustStoreManager tsm;
  private KeyPairManager kpm;
  private CertificateGenerator certGen;
  private CertificateSigningRequestSubmitter requestSubmitter;

  @Reference(cardinality = OPTIONAL, policy = DYNAMIC)
  private volatile ConfigurationAdmin configurationAdmin;

  @Activate
  void start(BundleContext ctx, Config config) throws ConfigurationException {

    String configPath = config.storage_folder();

    Path rootPath =
        configPath.isEmpty() ? ctx.getDataFile("management").toPath() : Paths.get(configPath);

    try {
      Path keystoreFolder = rootPath.resolve("keystores");
      Files.createDirectories(keystoreFolder);
      ksm = new KeyStoreManager(keystoreFolder, provider, secureRandom);

      Path truststoreFolder = rootPath.resolve("truststores");
      Files.createDirectories(truststoreFolder);
      tsm = new TrustStoreManager(truststoreFolder, provider, secureRandom);

      Path keysFolder = rootPath.resolve("keys");
      Files.createDirectories(keysFolder);
      kpm = new KeyPairManager(keysFolder, provider, secureRandom);
    } catch (IOException ioe) {
      throw new ConfigurationException(
          "storage.folder", "Failed to set up the storage folder", ioe);
    }

    certGen = new CertificateGenerator(provider, secureRandom);
    requestSubmitter = new CertificateSigningRequestSubmitter(tsm, secureRandom);

    ConfigurationAdmin cfgAdmin = configurationAdmin;

    if (cfgAdmin != null) {
      try {
        Configuration[] configs = cfgAdmin.listConfigurations(EXISTING_CONFIG_FILTER);
        if (configs != null) {
          for (Configuration cfg : configs) {
            try {
              cfg.update();
            } catch (Exception e) {
              // TODO log
            }
          }
        }
      } catch (Exception e) {
        // TODO log
      }
    }
  }

  @Override
  public void configurationEvent(ConfigurationEvent event) {
    if (event.getType() == ConfigurationEvent.CM_DELETED) {
      synchronized (lock) {
        referencedKeyStores.remove(event.getPid());
        referencedTrustStores.remove(event.getPid());
      }
    }
  }

  @Override
  public void modifyConfiguration(
      ServiceReference<?> reference, Dictionary<String, Object> properties) {
    int state;

    synchronized (lock) {
      state = this.state;
    }

    String pid = String.valueOf(properties.get(SERVICE_PID));

    List<String> keyStorelocations =
        converter
            .convert(properties.get(KEYSTORE_LOCATION))
            .defaultValue(emptyList())
            .to(LIST_OF_STRINGS);

    List<String> keyStoreTypes =
        converter
            .convert(properties.get(KEYSTORE_TYPE))
            .defaultValue(emptyList())
            .to(LIST_OF_STRINGS);

    List<String> keyStorePasswords =
        converter
            .convert(properties.get(KEYSTORE_PW))
            .defaultValue(emptyList())
            .to(LIST_OF_STRINGS);

    Set<String> keyStores =
        decorateStore(pid, keyStorelocations, keyStoreTypes, keyStorePasswords, ksm, properties);

    List<String> keyStoreAliases =
        converter
            .convert(properties.get(KEYSTORE_ALIAS))
            .defaultValue(emptyList())
            .to(LIST_OF_STRINGS);

    fillIn(keyStoreAliases, properties, s -> s.toLowerCase(Locale.ROOT));

    List<String> trustStorelocations =
        converter
            .convert(properties.get(TRUSTSTORE_LOCATION))
            .defaultValue(emptyList())
            .to(LIST_OF_STRINGS);

    List<String> trustStoreTypes =
        converter
            .convert(properties.get(TRUSTSTORE_TYPE))
            .defaultValue(emptyList())
            .to(LIST_OF_STRINGS);

    List<String> trustStorePasswords =
        converter
            .convert(properties.get(TRUSTSTORE_PW))
            .defaultValue(emptyList())
            .to(LIST_OF_STRINGS);

    Set<String> trustStores =
        decorateStore(
            pid, trustStorelocations, trustStoreTypes, trustStorePasswords, tsm, properties);

    boolean triggerUpdate;
    synchronized (lock) {
      referencedKeyStores.put(pid, keyStores);
      referencedTrustStores.put(pid, trustStores);
      triggerUpdate = state != this.state;
    }

    if (triggerUpdate) {
      triggerUpdate(pid);
    }
  }

  private void triggerUpdate(String pid) {
    var cfgAdmin = configurationAdmin;
    try {
      Configuration[] cfg = cfgAdmin.listConfigurations(String.format(PID_FILTER_TEMPLATE, pid));
      if (cfg != null) {
        cfg[0].update();
      }
    } catch (Exception e) {
      throw new SslException(e);
    }
  }

  private static final Pattern selector = Pattern.compile("^\\$\\{([\\w\\.-]+)\\}$");

  private Set<String> decorateStore(
      String pid,
      List<String> storelocations,
      List<String> storeTypes,
      List<String> storePasswords,
      AbstractStoreManager storeManager,
      Dictionary<String, Object> properties) {

    Map<String, StoreInfo> stores =
        storelocations.stream()
            .map(properties::get)
            .flatMap(
                o -> converter.convert(o).defaultValue(emptyList()).to(LIST_OF_STRINGS).stream())
            .map(selector::matcher)
            .filter(Matcher::matches)
            .map(m -> m.group(1))
            .distinct()
            .collect(toMap(identity(), storeName -> storeManager.getStoreFor(storeName, pid)));

    fillIn(storelocations, properties, store -> stores.get(store).location);
    fillIn(storeTypes, properties, store -> stores.get(store).type);
    fillIn(
        storePasswords,
        properties,
        store -> {
          // TODO log if missing?
          return stores.get(store).password;
        });

    return new HashSet<>(stores.keySet());
  }

  private void fillIn(
      List<String> storelocations,
      Dictionary<String, Object> properties,
      Function<String, String> replacer) {
    Map<String, Object> replaced =
        storelocations.stream()
            .distinct()
            .collect(toMap(identity(), s -> fillIn(properties.get(s), replacer)));

    replaced.values().removeIf(o -> o == null);

    replaced.forEach((k, v) -> properties.put(k, v));
  }

  private Object fillIn(Object object, Function<String, String> replacer) {
    if (object == null) {
      return null;
    }

    if (object instanceof Collection || object.getClass().isArray()) {
      boolean modified = false;
      List<String> list = converter.convert(object).to(LIST_OF_STRINGS);

      List<String> toReturn = new ArrayList<>(list.size());

      for (String s : list) {
        Matcher matcher = selector.matcher(s);
        if (matcher.matches()) {
          modified = true;
          toReturn.add(replacer.apply(matcher.group(1)));
        } else {
          toReturn.add(s);
        }
      }

      return modified ? toReturn : null;
    } else {
      Matcher matcher = selector.matcher(String.valueOf(object));
      return matcher.matches() ? replacer.apply(matcher.group(1)) : null;
    }
  }

  @Override
  public Collection<String> listKeyPairs() {
    return new ArrayList<>(kpm.listKeyPairs().keySet());
  }

  @Override
  public KeyPairInfo getKeyPairInfo(String keyPairName) {
    return kpm.getKeyPairInfo(keyPairName);
  }

  @Override
  public void createKeyPair(String keyPairName) {
    kpm.newKeyPair(keyPairName);
  }

  @Override
  public Collection<String> listKeyStores() {
    return new ArrayList<>(ksm.listKeyStores().keySet());
  }

  @Override
  public CertificateInfo getCertificateInfo(String keystoreName) {
    return ksm.getCertificateInfo(keystoreName);
  }

  @Override
  public Collection<String> listTrustStores() {
    return new ArrayList<>(tsm.listTrustStores().keySet());
  }

  @Override
  public Collection<CertificateInfo> getTrustedCertificateInfo(String truststoreName) {
    return tsm.getCertificateInfo(truststoreName);
  }

  @Override
  public String createNewCertificateSigningRequest(String certificateName, String keyPairName) {
    return certGen.generateCertificateSigningRequest(kpm.getKeyPair(keyPairName), certificateName);
  }

  @Override
  public String issueCertificateSigningRequest(
      URL url, String signingRequest, String oneTimePasscode, String encodedCertificates) {
    return requestSubmitter.issueCertificateSigningRequest(
        url, signingRequest, oneTimePasscode, encodedCertificates);
  }

  @Override
  public void createTrustStore(String trustStoreName, String encodedCertificates) {
    tsm.createTrustStore(trustStoreName, encodedCertificates);
  }

  @Override
  public void addTrustedCertificates(String trustStoreName, String encodedCertificates) {
    tsm.addTrustedCertificates(trustStoreName, encodedCertificates);
  }

  @Override
  public void deleteTrustStore(String trustStoreName) {
    tsm.deleteStore(trustStoreName);
  }

  @Override
  public void removeTrustedCertificate(String trustStore, String certificateAlias) {
    tsm.removeTrustedCertificate(trustStore, certificateAlias);
  }

  @Override
  public void createKeyStore(
      String keystoreName, String keyPairName, String encodedCertificateAndChain) {
    ksm.createKeyStore(keystoreName, kpm.getKeyPair(keyPairName), encodedCertificateAndChain);
  }

  @Override
  public void updateKeyStore(
      String keystoreName, String keyPairName, String encodedCertificateAndChain) {
    ksm.updateKeyStore(keystoreName, kpm.getKeyPair(keyPairName), encodedCertificateAndChain);
  }

  @Override
  public void deleteKeyStore(String keystoreName) {
    ksm.deleteStore(keystoreName);
  }

  @Override
  public String signCertificateSigningRequest(String keystoreName, String signingRequest) {
    return certGen.signCertificate(ksm.getSignerInfo(keystoreName), signingRequest);
  }

  @Override
  public String getCertificateChain(String keystoreName) {
    return ksm.getCertificateChain(keystoreName);
  }

  @Override
  public void createCertificateAuthority(String certificateName) {
    KeyPair newKeyPair = kpm.newKeyPair(certificateName);
    Certificate cert =
        certGen.generateRootCertificate(newKeyPair, certificateName, Duration.ofDays(365));
    ksm.createKeyStore(certificateName, newKeyPair, new Certificate[] {cert});
  }
}
