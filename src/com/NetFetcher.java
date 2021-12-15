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

	public String[] icmpInfoArr;   	//icpm���ݰ�����
	public String[] tcpInfoArr;		//tcp���ݰ�����
	public String[] egpInfoArr;		//egp���ݰ�����
	public String[] updInfoArr;		//udp���ݰ�����
	
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
        //����Э������
        if(packet instanceof ARPPacket) { //��Э���޶˿ں�
            ARPPacket arpPacket = (ARPPacket) packet;
            infoMap.put("ContractType", "ARPЭ��");
            infoMap.put("Caplen", String.valueOf(arpPacket.caplen));
            infoMap.put("SecTime", String.valueOf(arpPacket.sec));
            infoMap.put("SourceIp", arpPacket.getSenderProtocolAddress().toString().replace("/", ""));
            infoMap.put("SourceMacAddr", arpPacket.getSenderHardwareAddress().toString());
            infoMap.put("TargetIp", arpPacket.getTargetProtocolAddress().toString().replace("/", ""));
            infoMap.put("TargetMacAddr", arpPacket.getTargetHardwareAddress().toString());
        } else if(packet instanceof UDPPacket) {
            UDPPacket udpPacket = (UDPPacket) packet;
            EthernetPacket datalink = (EthernetPacket) udpPacket.datalink;
            infoMap.put("ContractType", "UDPЭ��");
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
            infoMap.put("ContractType", "TCPЭ��");
            infoMap.put("Caplen", String.valueOf(tcpPacket.caplen));
            infoMap.put("SecTime", String.valueOf(tcpPacket.sec));
            infoMap.put("SourceIp", tcpPacket.src_ip.getHostAddress());
            infoMap.put("SourcePort", String.valueOf(tcpPacket.src_port));
            
            infoMap.put("SourceMacAddr", getMacInfo(datalink.src_mac));
            infoMap.put("TargetIp", tcpPacket.dst_ip.getHostAddress());
            infoMap.put("TargetPort", String.valueOf(tcpPacket.dst_port));
            infoMap.put("TargetMacAddr", getMacInfo(datalink.dst_mac));
        } else if(packet instanceof ICMPPacket) { //��Э���޶˿ں�
        	System.out.println("ICMPPacket");
            ICMPPacket icmpPacket = (ICMPPacket) packet;
            EthernetPacket datalink = (EthernetPacket) icmpPacket.datalink;
            infoMap.put("ContractType", "ICMPЭ��");
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
//            log.info("ץȡ����װ�뻺��ʱ �����쳣�����飺" + e);
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
