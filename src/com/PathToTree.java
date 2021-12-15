package com;

//package com.cn.test;

import java.io.IOException;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import java.util.ArrayList;
import java.util.List;
import com.alibaba.fastjson.JSONObject;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;   
import com.alibaba.fastjson.JSON;
public class PathToTree {
	public static void main(String[] args) {
		System.out.println("ok`````");
	}
	public static void start() {
		Capture.startCapture();
	}
	public static void stop() {
		Capture.stopCapture();
	}
	public static String[] getInfo() {
		return Capture.getCpatureInfo();
	}
}
	
