package info.galudisu;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class ConsoleOutput {

  private String message;

  public ConsoleOutput(String message) {
    this.message = message;
  }

  public static ConsoleOutput of(String message) {
    return new ConsoleOutput(message);
  }

  public static String ofPretty(String message) {
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    return gson.toJson(ConsoleOutput.of(message));
  }

  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }
}
