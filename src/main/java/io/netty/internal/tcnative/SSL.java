//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package io.netty.internal.tcnative;

public final class SSL {
    public static final int SSL_PROTOCOL_NONE = 0;
    public static final int SSL_PROTOCOL_SSLV2 = 1;
    public static final int SSL_PROTOCOL_SSLV3 = 2;
    public static final int SSL_PROTOCOL_TLSV1 = 4;
    public static final int SSL_PROTOCOL_TLSV1_1 = 8;
    public static final int SSL_PROTOCOL_TLSV1_2 = 16;
    public static final int SSL_PROTOCOL_TLSV1_3 = 32;
    public static final int SSL_PROTOCOL_DTLS = 64;
    public static final int SSL_PROTOCOL_DTLSV1 = 128;
    public static final int SSL_PROTOCOL_DTLSV1_2 = 256;
    public static final int SSL_PROTOCOL_TLS = 62;
    public static final int SSL_PROTOCOL_DLS = 63;
    public static final int SSL_PROTOCOL_ALL = 64;
    public static final int SSL_CVERIFY_IGNORED = -1;
    public static final int SSL_CVERIFY_NONE = 0;
    public static final int SSL_CVERIFY_OPTIONAL = 1;
    public static final int SSL_CVERIFY_REQUIRED = 2;
    public static final int SSL_OP_CIPHER_SERVER_PREFERENCE = NativeStaticallyReferencedJniMethods.sslOpCipherServerPreference();
    public static final int SSL_OP_NO_SSLv2 = NativeStaticallyReferencedJniMethods.sslOpNoSSLv2();
    public static final int SSL_OP_NO_SSLv3 = NativeStaticallyReferencedJniMethods.sslOpNoSSLv3();
    public static final int SSL_OP_NO_TLSv1 = NativeStaticallyReferencedJniMethods.sslOpNoTLSv1();
    public static final int SSL_OP_NO_TLSv1_1 = NativeStaticallyReferencedJniMethods.sslOpNoTLSv11();
    public static final int SSL_OP_NO_TLSv1_2 = NativeStaticallyReferencedJniMethods.sslOpNoTLSv12();
    public static final int SSL_OP_NO_TLSv1_3 = NativeStaticallyReferencedJniMethods.sslOpNoTLSv13();
    public static final int SSL_OP_NO_TICKET = NativeStaticallyReferencedJniMethods.sslOpNoTicket();
    public static final int SSL_OP_NO_COMPRESSION = NativeStaticallyReferencedJniMethods.sslOpNoCompression();
    public static final int SSL_MODE_CLIENT = 0;
    public static final int SSL_MODE_SERVER = 1;
    public static final int SSL_MODE_COMBINED = 2;
    public static final long SSL_SESS_CACHE_OFF = (long)NativeStaticallyReferencedJniMethods.sslSessCacheOff();
    public static final long SSL_SESS_CACHE_SERVER = (long)NativeStaticallyReferencedJniMethods.sslSessCacheServer();
    public static final long SSL_SESS_CACHE_CLIENT = (long)NativeStaticallyReferencedJniMethods.sslSessCacheClient();
    public static final long SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = (long)NativeStaticallyReferencedJniMethods.sslSessCacheNoInternalLookup();
    public static final long SSL_SESS_CACHE_NO_INTERNAL_STORE = (long)NativeStaticallyReferencedJniMethods.sslSessCacheNoInternalStore();
    public static final int SSL_SELECTOR_FAILURE_NO_ADVERTISE = 0;
    public static final int SSL_SELECTOR_FAILURE_CHOOSE_MY_LAST_PROTOCOL = 1;
    public static final int SSL_ST_CONNECT = NativeStaticallyReferencedJniMethods.sslStConnect();
    public static final int SSL_ST_ACCEPT = NativeStaticallyReferencedJniMethods.sslStAccept();
    public static final int SSL_MODE_ENABLE_PARTIAL_WRITE = NativeStaticallyReferencedJniMethods.sslModeEnablePartialWrite();
    public static final int SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = NativeStaticallyReferencedJniMethods.sslModeAcceptMovingWriteBuffer();
    public static final int SSL_MODE_RELEASE_BUFFERS = NativeStaticallyReferencedJniMethods.sslModeReleaseBuffers();
    public static final int SSL_MODE_ENABLE_FALSE_START = NativeStaticallyReferencedJniMethods.sslModeEnableFalseStart();
    public static final int SSL_MAX_PLAINTEXT_LENGTH = NativeStaticallyReferencedJniMethods.sslMaxPlaintextLength();
    public static final int SSL_MAX_RECORD_LENGTH = NativeStaticallyReferencedJniMethods.sslMaxRecordLength();
    public static final int X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT = NativeStaticallyReferencedJniMethods.x509CheckFlagAlwaysCheckSubject();
    public static final int X509_CHECK_FLAG_NO_WILD_CARDS = NativeStaticallyReferencedJniMethods.x509CheckFlagDisableWildCards();
    public static final int X509_CHECK_FLAG_NO_PARTIAL_WILD_CARDS = NativeStaticallyReferencedJniMethods.x509CheckFlagNoPartialWildCards();
    public static final int X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS = NativeStaticallyReferencedJniMethods.x509CheckFlagMultiLabelWildCards();
    public static final int SSL_SENT_SHUTDOWN = NativeStaticallyReferencedJniMethods.sslSendShutdown();
    public static final int SSL_RECEIVED_SHUTDOWN = NativeStaticallyReferencedJniMethods.sslReceivedShutdown();
    public static final int SSL_ERROR_NONE = NativeStaticallyReferencedJniMethods.sslErrorNone();
    public static final int SSL_ERROR_SSL = NativeStaticallyReferencedJniMethods.sslErrorSSL();
    public static final int SSL_ERROR_WANT_READ = NativeStaticallyReferencedJniMethods.sslErrorWantRead();
    public static final int SSL_ERROR_WANT_WRITE = NativeStaticallyReferencedJniMethods.sslErrorWantWrite();
    public static final int SSL_ERROR_WANT_X509_LOOKUP = NativeStaticallyReferencedJniMethods.sslErrorWantX509Lookup();
    public static final int SSL_ERROR_SYSCALL = NativeStaticallyReferencedJniMethods.sslErrorSyscall();
    public static final int SSL_ERROR_ZERO_RETURN = NativeStaticallyReferencedJniMethods.sslErrorZeroReturn();
    public static final int SSL_ERROR_WANT_CONNECT = NativeStaticallyReferencedJniMethods.sslErrorWantConnect();
    public static final int SSL_ERROR_WANT_ACCEPT = NativeStaticallyReferencedJniMethods.sslErrorWantAccept();
    public static final int SSL_ERROR_WANT_PRIVATE_KEY_OPERATION = NativeStaticallyReferencedJniMethods.sslErrorWantPrivateKeyOperation();
    public static final int SSL_ERROR_WANT_CERTIFICATE_VERIFY = NativeStaticallyReferencedJniMethods.sslErrorWantCertificateVerify();

    private SSL() {
    }

    public static native int version();

    public static native String versionString();

    static native int initialize(String var0);

    public static native long newMemBIO() throws Exception;

    public static native String getLastError();

    public static native long newSSL(long var0, boolean var2);

    public static native int getError(long var0, int var2);

    public static native int bioWrite(long var0, long var2, int var4);

    public static native long bioNewByteBuffer(long var0, int var2);

    public static native void bioSetByteBuffer(long var0, long var2, int var4, boolean var5);

    public static native void bioClearByteBuffer(long var0);

    public static native int bioFlushByteBuffer(long var0);

    public static native int bioLengthByteBuffer(long var0);

    public static native int bioLengthNonApplication(long var0);

    public static native int sslPending(long var0);

    public static native int writeToSSL(long var0, long var2, int var4);

    public static native int readFromSSL(long var0, long var2, int var4);

    public static native int getShutdown(long var0);

    public static native void setShutdown(long var0, int var2);

    public static native void freeSSL(long var0);

    public static native void freeBIO(long var0);

    public static native int shutdownSSL(long var0);

    public static native int getLastErrorNumber();

    public static native String getCipherForSSL(long var0);

    public static native String getVersion(long var0);

    public static native int doHandshake(long var0);

    public static native int isInInit(long var0);

    public static native String getNextProtoNegotiated(long var0);

    public static native String getAlpnSelected(long var0);

    public static native byte[][] getPeerCertChain(long var0);

    public static native byte[] getPeerCertificate(long var0);

    public static native String getErrorString(long var0);

    public static native long getTime(long var0);

    public static native long getTimeout(long var0);

    public static native long setTimeout(long var0, long var2);

    public static native void setVerify(long var0, int var2, int var3);

    public static native void setOptions(long var0, int var2);

    public static native void clearOptions(long var0, int var2);

    public static native int getOptions(long var0);

    public static native int setMode(long var0, int var2);

    public static native int getMode(long var0);

    public static native int getMaxWrapOverhead(long var0);

    public static native String[] getCiphers(long var0);

    /** @deprecated */
    @Deprecated
    public static boolean setCipherSuites(long ssl, String ciphers) throws Exception {
        return setCipherSuites(ssl, ciphers, false);
    }

    public static native boolean setCipherSuites(long var0, String var2, boolean var3) throws Exception;

    public static native byte[] getSessionId(long var0);

    public static native int getHandshakeCount(long var0);

    public static native void clearError();

    public static void setTlsExtHostName(long ssl, String hostname) {
        if (hostname != null && hostname.endsWith(".")) {
            hostname = hostname.substring(0, hostname.length() - 1);
        }

        setTlsExtHostName0(ssl, hostname);
    }

    private static native void setTlsExtHostName0(long var0, String var2);

    public static native void setHostNameValidation(long var0, int var2, String var3);

    public static native String[] authenticationMethods(long var0);

    /** @deprecated */
    @Deprecated
    public static native void setCertificateChainBio(long var0, long var2, boolean var4);

    /** @deprecated */
    @Deprecated
    public static native void setCertificateBio(long var0, long var2, long var4, String var6) throws Exception;

    public static native long loadPrivateKeyFromEngine(String var0, String var1) throws Exception;

    public static native long parsePrivateKey(long var0, String var2) throws Exception;

    public static native void freePrivateKey(long var0);

    public static native long parseX509Chain(long var0) throws Exception;

    public static native void freeX509Chain(long var0);

    public static native void enableOcsp(long var0);

    /** @deprecated */
    @Deprecated
    public static void setKeyMaterialServerSide(long ssl, long chain, long key) throws Exception {
        setKeyMaterial(ssl, chain, key);
    }

    public static native void setKeyMaterial(long var0, long var2, long var4) throws Exception;

    /** @deprecated */
    @Deprecated
    public static native void setKeyMaterialClientSide(long var0, long var2, long var4, long var6, long var8) throws Exception;

    public static native void setOcspResponse(long var0, byte[] var2);

    public static native byte[] getOcspResponse(long var0);

    public static native void fipsModeSet(int var0) throws Exception;

    public static native String getSniHostname(long var0);

    public static native String[] getSigAlgs(long var0);

    public static native byte[] getMasterKey(long var0);

    public static native byte[] getServerRandom(long var0);

    public static native byte[] getClientRandom(long var0);

    public static native Runnable getTask(long var0);

    public static native boolean isSessionReused(long var0);

    public static native boolean setSession(long var0, long var2);

    public static native long getSession(long var0);
}
