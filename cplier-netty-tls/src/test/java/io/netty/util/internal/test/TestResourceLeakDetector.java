package io.netty.util.internal.test;

import io.netty.util.ResourceLeakDetector;

import java.util.List;
import java.util.Vector;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestResourceLeakDetector<T> extends ResourceLeakDetector<T> {

  private static final List<String> leaks = new Vector<>();

  public TestResourceLeakDetector(Class<T> resourceType, int samplingInterval) {
    super(resourceType, samplingInterval);
  }

  public TestResourceLeakDetector(Class<T> resourceType, int samplingInterval, long l) {
    super(resourceType, samplingInterval);
  }

  @Override
  protected void reportTracedLeak(String resourceType, String records) {
    leaks.add("\nRecord:\n" + resourceType + "\n" + records + "\n");
    super.reportTracedLeak(resourceType, records);
  }

  @Override
  protected void reportUntracedLeak(String resourceType) {
    leaks.add("\nRecord:\n" + resourceType + "\n");
    super.reportUntracedLeak(resourceType);
  }

  public static void assertNoLeaks() {
    System.gc();
    assertEquals("[]", leaks.toString());
    assertTrue(leaks.isEmpty());
    leaks.clear();
  }
}
