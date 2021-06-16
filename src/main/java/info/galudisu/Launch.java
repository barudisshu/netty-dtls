package info.galudisu;

public interface Launch extends Dispatch {

  Integer CPU_CORE = Runtime.getRuntime().availableProcessors();

  void createEventLoopGroup();

  void startServer();

  void closeChannel();

  void shutdownGraceFully();
}
