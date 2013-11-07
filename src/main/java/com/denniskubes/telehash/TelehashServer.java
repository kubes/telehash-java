package com.denniskubes.telehash;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;

import org.apache.commons.lang.math.NumberUtils;

public class TelehashServer {

  private int port = 4222;

  public TelehashServer(int port) {
    this.port = port;
  }

  public void run()
    throws Exception {

    EventLoopGroup group = new NioEventLoopGroup();

    try {
      
      Bootstrap bootstrap = new Bootstrap();
      bootstrap.group(group);
      bootstrap.channel(NioDatagramChannel.class);
      bootstrap.handler(new TelehashHandler());

      ChannelFuture cf = bootstrap.bind(port).sync();
      cf.channel().closeFuture().sync();
    }
    finally {
      group.shutdownGracefully();
    }
  }

  public static void main(String[] args)
    throws Exception {

    int port = 4222;
    if (args.length > 0) {
      port = NumberUtils.toInt(args[0]);
    }
    new TelehashServer(port).run();
  }

}
