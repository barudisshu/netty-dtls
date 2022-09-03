package info.galudisu;

public interface Launch extends Dispatch {

  void createEventLoopGroup();

  void startServer();

  void closeChannel();

  void shutdownGraceFully();
}
