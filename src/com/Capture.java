package com;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import java.io.IOException;;

public class Capture {
	public static final NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	public static NetworkInterface[] arr = new NetworkInterface[devices.length];
	public static JpcapCaptor jpcapCaptor;
	//public static
	public static void main(String[] args) {
		Capture.startCapture();
		Capture.stopCapture();
		System.out.println(NetFetcher.getInfoArr());
	}
	public static void startCapture() {
		try {
	    	 jpcapCaptor = JpcapCaptor.openDevice(devices[0], 2000, false, 20);
	    	 jpcapCaptor.setFilter("ip", true);
	    	 jpcapCaptor.loopPacket(10, new NetFetcher("ip"));
	     } catch (IOException e) {
	    	 e.printStackTrace();
	     }
	}
	public static void stopCapture() {
		jpcapCaptor.breakLoop();
	}
	public static String[] getCpatureInfo() {
		return NetFetcher.getInfoArr();
	}
}
