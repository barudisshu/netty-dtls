package io.netty.util.internal.dtls.adapter;

import io.netty.buffer.ByteBuf;
import io.netty.util.internal.dtls.adapter.DtlsEngineResult.OperationRequired;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

public interface DtlsEngine {

  DtlsEngineResult generateDataToSend(ByteBuf input, ByteBuf output) throws SSLException;

  DtlsEngineResult handleReceivedData(ByteBuf input, ByteBuf output) throws SSLException;

  Runnable getTaskToRun();

  void closeOutbound();

  SSLParameters getSSLParameters();

  int getMaxSendOutputBufferSize();

  int getMaxReceiveOutputBufferSize();

  void setClient(boolean isClient);

  boolean isClient();

  OperationRequired getOperationRequired();

  void startHandshaking() throws SSLException;
}
