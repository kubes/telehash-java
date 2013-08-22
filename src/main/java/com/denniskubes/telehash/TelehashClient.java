package com.denniskubes.telehash;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;

import java.net.InetSocketAddress;

public class TelehashClient {

  private int port;

  public TelehashClient(int port) {
    this.port = port;
  }

  public void run()
    throws Exception {

    EventLoopGroup group = new NioEventLoopGroup();
    try {

      Bootstrap bootstrap = new Bootstrap();
      bootstrap.group(group);
      bootstrap.channel(NioDatagramChannel.class);
      bootstrap.option(ChannelOption.SO_BROADCAST, true);
      bootstrap.handler(new TelehashClientHandler());

      Channel ch = bootstrap.bind(0).sync().channel();
      String testJSON = "{ \"hello\" : \"world\" }";

      ByteBuf data = Unpooled.buffer(1000);
      data.writeShort((short)testJSON.length());
      data.writeBytes(testJSON.getBytes());

      DatagramPacket packet = new DatagramPacket(data, new InetSocketAddress(
        "255.255.255.255", port));

      ch.writeAndFlush(packet).sync();

      if (!ch.closeFuture().await(150000)) {
        System.err.println("Telehash request timed out.");
      }
    }
    finally {
      group.shutdownGracefully();
    }
  }

  public static void main(String[] args)
    throws Exception {
    int port;
    if (args.length > 0) {
      port = Integer.parseInt(args[0]);
    }
    else {
      port = 4222;
    }
    new TelehashClient(port).run();
  }

}
