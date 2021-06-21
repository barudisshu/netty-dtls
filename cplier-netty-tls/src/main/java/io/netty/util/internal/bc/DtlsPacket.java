package io.netty.util.internal.bc;

import io.netty.channel.socket.DatagramPacket;

public class DtlsPacket {

    public final DatagramPacket packet;

    DtlsPacket(DatagramPacket packet) {
        this.packet = packet;
    }
}