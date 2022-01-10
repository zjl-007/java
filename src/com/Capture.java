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
	public static JpcapCaptor jpcapCaptor = null;
	public NetFetcher netfetcher;
	public static void main(String[] args) {
//		Capture.startCapture(10);
	}
	public Capture() {
		
	}
	public void startCapture(int index, int count, String content)  {
		NetFetcher.arrayList.clear();   //抓包之前先清空上次抓的数据
		System.out.println("网卡：" + index + ";抓包数量：" + count + ";抓包条件：" + content);
		try {
			NetFetcher.isCaptureing = true;
	    	 jpcapCaptor = JpcapCaptor.openDevice(devices[index], 2000, false, 20);
	    	 jpcapCaptor.setFilter(content, true);
//	    	 jpcapCaptor.setFilter("dst host 192.168.1.126", true);
//	    	 jpcapCaptor.setFilter("ip and tcp and dst port 80", true);
	    	 netfetcher = new NetFetcher(count);
	    	 jpcapCaptor.loopPacket(count, netfetcher);
	     } catch (IOException e) {
	    	 e.printStackTrace();
	 		NetFetcher.isCaptureing = false;
	     }
	}
	public boolean getCaptureState() {
		return NetFetcher.isCaptureing;
	}
	public void stopCapture(Thread captureThread) {
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		if(Capture.jpcapCaptor == null) {
			return;
		}
		Capture.jpcapCaptor.close();
		NetFetcher.isCaptureing = false;
		NetFetcher.currentPack = 0;
	}
	public String[] getCpatureInfo() {
		return NetFetcher.getInfoArr();
	}
	
	public String[] getDevicesInfo() {
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
