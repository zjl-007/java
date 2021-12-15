package com;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.alibaba.fastjson.JSON;

import jpcap.PacketReceiver;
import jpcap.packet.*;
import jpcap.packet.Packet;

class NetFetcher implements PacketReceiver{
	public static String packetType = "";
	public static ArrayList<String> arrayList = new ArrayList<>();
	
	public ICMPPacket icmp = null;
	public UDPPacket udp = null;

	public String[] icmpInfoArr;   	//icpm数据包数组
	public String[] tcpInfoArr;		//tcp数据包数组
	public String[] egpInfoArr;		//egp数据包数组
	public String[] updInfoArr;		//udp数据包数组
	
	public static Map<String, String> infoMap;
	public NetFetcher(String type) {
		NetFetcher.packetType = type;
	}
	@Override
	public void receivePacket(Packet packet) {
//		if(NetFetcher.packetType == "" ) {
//			arrayList.add(JSON.toJSONString(arg0));
//		} else if (NetFetcher.packetType == "ip") {
//			IPPacket ip = (IPPacket) arg0;
//			int protocolNum = ip.protocol;
//			switch(protocolNum) {
//				case 1: {
//						icmp = (ICMPPacket) ip;
//						
//						break;
//					}
//				case 17: udp = (UDPPacket) ip;break;
//			};
//			System.out.println(icmp);
//
//			System.out.println(JSON.toJSONString(udp));
//			//System.out.println(ip.protocol);
//			if(ip.protocol == 17) {
//				System.out.println(JSON.toJSONString(ip));
//			}
//			arrayList.add(JSON.toJSONString(ip));
//		} else if (NetFetcher.packetType == "icmp") {
//			ICMPPacket icmp = (ICMPPacket) arg0;
//			System.out.println(JSON.toJSONString(icmp));
//		}
//		System.out.println(JSON.toJSONString(arg0));
		
		
		infoMap = new HashMap<>();
        //分析协议类型
        if(packet instanceof ARPPacket) { //该协议无端口号
            ARPPacket arpPacket = (ARPPacket) packet;
            infoMap.put("ContractType", "ARP协议");
            infoMap.put("Caplen", String.valueOf(arpPacket.caplen));
            infoMap.put("SecTime", String.valueOf(arpPacket.sec));
            infoMap.put("SourceIp", arpPacket.getSenderProtocolAddress().toString().replace("/", ""));
            infoMap.put("SourceMacAddr", arpPacket.getSenderHardwareAddress().toString());
            infoMap.put("TargetIp", arpPacket.getTargetProtocolAddress().toString().replace("/", ""));
            infoMap.put("TargetMacAddr", arpPacket.getTargetHardwareAddress().toString());
        } else if(packet instanceof UDPPacket) {
            UDPPacket udpPacket = (UDPPacket) packet;
            EthernetPacket datalink = (EthernetPacket) udpPacket.datalink;
            infoMap.put("ContractType", "UDP协议");
            infoMap.put("Caplen", String.valueOf(udpPacket.caplen));
            infoMap.put("SecTime", String.valueOf(udpPacket.sec));
            infoMap.put("SourceIp", udpPacket.src_ip.getHostAddress());
            infoMap.put("SourcePort", String.valueOf(udpPacket.src_port));
            
            infoMap.put("SourceMacAddr", getMacInfo(datalink.src_mac));
            infoMap.put("TargetIp", udpPacket.dst_ip.getHostAddress());
            infoMap.put("TargetPort", String.valueOf(udpPacket.dst_port));
            infoMap.put("TargetMacAddr", getMacInfo(datalink.dst_mac));
        } else if(packet instanceof TCPPacket) {
            TCPPacket tcpPacket = (TCPPacket) packet;
            EthernetPacket datalink = (EthernetPacket) tcpPacket.datalink;
            infoMap.put("ContractType", "TCP协议");
            infoMap.put("Caplen", String.valueOf(tcpPacket.caplen));
            infoMap.put("SecTime", String.valueOf(tcpPacket.sec));
            infoMap.put("SourceIp", tcpPacket.src_ip.getHostAddress());
            infoMap.put("SourcePort", String.valueOf(tcpPacket.src_port));
            
            infoMap.put("SourceMacAddr", getMacInfo(datalink.src_mac));
            infoMap.put("TargetIp", tcpPacket.dst_ip.getHostAddress());
            infoMap.put("TargetPort", String.valueOf(tcpPacket.dst_port));
            infoMap.put("TargetMacAddr", getMacInfo(datalink.dst_mac));
        } else if(packet instanceof ICMPPacket) { //该协议无端口号
        	System.out.println("ICMPPacket");
            ICMPPacket icmpPacket = (ICMPPacket) packet;
            EthernetPacket datalink = (EthernetPacket) icmpPacket.datalink;
            infoMap.put("ContractType", "ICMP协议");
            infoMap.put("Caplen", String.valueOf(icmpPacket.caplen));
            infoMap.put("SecTime", String.valueOf(icmpPacket.sec));
            infoMap.put("SourceIp", icmpPacket.src_ip.getHostAddress());
            
            infoMap.put("SourceMacAddr", getMacInfo(datalink.src_mac));
            infoMap.put("TargetIp", icmpPacket.dst_ip.getHostAddress());
            infoMap.put("TargetMacAddr", getMacInfo(datalink.dst_mac));
        }
        arrayList.add(JSON.toJSONString(infoMap));
//        try {
//            CatchDataToCache catchDataToCache = new CatchDataToCacheImpl();
//            catchDataToCache.setInfoToCache(infoMap);
//        } catch (Exception e) {
//            log.info("抓取数据装入缓存时 出现异常，请检查：" + e);
//            jpcap.breakLoop();
//            if(jpcap != null) {
//                jpcap.close();
//            }
//        }
	}
	
	public static String[] getInfoArr() {
		int len = arrayList.size();
		String infoArr[] = new String[len];
		for(int i = 0; i < len; i++) {
			System.out.println(arrayList.get(i));
			infoArr[i] = arrayList.get(i);
		}
		return infoArr;
	}
	
	protected String getMacInfo(byte[] macByte) {
        StringBuffer srcMacStr = new StringBuffer(); 
        int count = 1;
        for (byte b : macByte) {  
            srcMacStr.append(Integer.toHexString(b & 0xff));
            if(count++ != macByte.length) 
                srcMacStr.append(":");
        }
        return srcMacStr.toString();
    }
}
