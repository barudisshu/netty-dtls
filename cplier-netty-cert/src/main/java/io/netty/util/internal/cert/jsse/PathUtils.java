package io.netty.util.internal.cert.jsse;

import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;

/** @author galudisu */
public final class PathUtils {

  private PathUtils() {
    throw new IllegalStateException("Utility class should not be instantiated");
  }

  private static final FileSystem DEFAULT = FileSystems.getDefault();

  public static Path get(String first, String... more) {
    return DEFAULT.getPath(first, more);
  }

  public static Path get(URI uri) {
    if (uri.getScheme().equalsIgnoreCase("file")) {
      return DEFAULT.provider().getPath(uri);
    } else {
      return Paths.get(uri);
    }
  }

  public static Path get(Path[] roots, String path) {
    for (Path root : roots) {
      Path normalizedRoot = root.normalize();
      Path normalizedPath = normalizedRoot.resolve(path).normalize();
      if (normalizedPath.startsWith(normalizedRoot)) {
        return normalizedPath;
      }
    }
    return null;
  }

  public static Path get(Path[] roots, URI uri) {
    return get(roots, PathUtils.get(uri).normalize().toString());
  }

  public static FileSystem getDefaultFileSystem() {
    return DEFAULT;
  }
}
