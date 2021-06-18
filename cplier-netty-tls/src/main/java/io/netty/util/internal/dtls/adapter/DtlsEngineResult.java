package io.netty.util.internal.dtls.adapter;

public interface DtlsEngineResult {

  OperationResult getOperationResult();

  OperationRequired getOperationRequired();

  enum OperationResult {
    INSUFFICIENT_INPUT,
    TOO_MUCH_OUTPUT,
    OK,
    ENGINE_CLOSED;
  }

  enum OperationRequired {
    NONE,
    RUN_TASK,
    DATA_TO_SEND,
    AWAITING_DATA,
    PENDING_RECEIVED_DATA;
  }
}
