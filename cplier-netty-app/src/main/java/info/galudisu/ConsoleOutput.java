package info.galudisu;

import com.google.gson.GsonBuilder;
import lombok.Getter;

/** @author galudisu */
@Getter
public class ConsoleOutput {

  private final String message;

  public ConsoleOutput(String message) {
    this.message = message;
  }

  public static ConsoleOutput of(String message) {
    return new ConsoleOutput(message);
  }

  public static String ofPretty(String message) {
    var gson = new GsonBuilder().setPrettyPrinting().create();
    return gson.toJson(ConsoleOutput.of(message));
  }
}
