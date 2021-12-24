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
//		String [] l = PathToTree.getDevicesInfo();
//		System.out.println(JSON.toJSONString(l));
		Capture.startCapture(-1);
	}
	public static void startCapture(int count) {
		Capture.startCapture(count);
	}
	public static void stopCapture() {
		Capture.stopCapture();
	}
	public static String[] getCaptureResult() {
		return Capture.getCpatureInfo();
	}
	public static String[] getDevicesInfo() {
		return Capture.getDevicesInfo();
	}
}
	
