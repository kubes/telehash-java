package com.denniskubes.telehash;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;
import io.netty.util.CharsetUtil;

import org.apache.commons.lang.StringUtils;

public class TelehashHandler
  extends SimpleChannelInboundHandler<DatagramPacket> {

  @Override
  public void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet)
    throws Exception {

    ByteBuf buff = packet.content();
    if (!buff.isReadable()) {
      return;
    }

    int length = (int)buff.readShort();
    byte[] jsonBytes = new byte[length];
    buff.readBytes(jsonBytes);
    String json = new String(jsonBytes);

    if (StringUtils.isNotBlank(json)) {
      ctx.write(new DatagramPacket(Unpooled.copiedBuffer(json,
        CharsetUtil.UTF_8), packet.sender()));
    }
  }

  @Override
  public void channelReadComplete(ChannelHandlerContext ctx)
    throws Exception {
    ctx.flush();
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
    throws Exception {
    cause.printStackTrace();
    // We don't close the channel because we can keep serving requests.
  }
}
