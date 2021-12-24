package com;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.alibaba.fastjson.JSON;;

public class Capture {
	public static final NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	public static NetworkInterface[] arr = new NetworkInterface[devices.length];
	public static JpcapCaptor jpcapCaptor;
	//public static
	public static void main(String[] args) {
//		Capture.startCapture(10);
	}
	public static void startCapture(int count) {
		try {
	    	 jpcapCaptor = JpcapCaptor.openDevice(devices[0], 2000, false, 20);
//	    	 jpcapCaptor.setFilter("ip", true);
	    	 jpcapCaptor.setFilter("ip", true);
//	    	 jpcapCaptor.setFilter("ip and tcp and dst port 80", true);
	    	 jpcapCaptor.loopPacket(count, new NetFetcher("ip"));
	     } catch (IOException e) {
	    	 e.printStackTrace();
	     }
	}
	public static void stopCapture() {
		jpcapCaptor.breakLoop();
		jpcapCaptor.close();
	}
	public static String[] getCpatureInfo() {
		return NetFetcher.getInfoArr();
	}
	
	public static String[] getDevicesInfo() {
		List<Map<String, Object>> list = NetFetcher.devices();
		int len = NetFetcher.devices().size();
		String infoArr[] = new String[len];
		for(int i = 0; i < len; i++) {
//			infoArr[i] = list.get(i).toString();
			infoArr[i] = JSON.toJSONString(list.get(i));
		}
		list.clear();
		return infoArr;
	}
}
