package com;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.alibaba.fastjson.JSON;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.PacketReceiver;
import jpcap.packet.*;
import jpcap.packet.Packet;

class NetFetcher implements PacketReceiver{
	public static ArrayList<String> arrayList = new ArrayList<>();
	
	public ICMPPacket icmp = null;
	public UDPPacket udp = null;

	public String[] icmpInfoArr;   	//icpm���ݰ�����
	public String[] tcpInfoArr;		//tcp���ݰ�����
	public String[] egpInfoArr;		//egp���ݰ�����
	public String[] updInfoArr;		//udp���ݰ�����
	
	public static Boolean isCaptureing = false;    //�ж��Ƿ���ץ��
	public static int currentPack = 1;			//���㵱ǰץ����
	public static int totalPack;			//Ӧ��ץ����Ŀ
	
	public static Map<String, String> infoMap;
	public NetFetcher(int packCount) {
		NetFetcher.totalPack = packCount;
	}
	
	public static List<Map<String, Object>> list = new ArrayList<>();
    /**
     * ɨ������е�������Ϣ
     */
    public static List<Map<String, Object>> devices() {
        //��װ������������Ϣ
        try{
            NetworkInterface[] devices = JpcapCaptor.getDeviceList();
            for (int i = 0; i < devices.length; i++) {
                Map<String, Object> networkCardMap = new HashMap<>();
                networkCardMap.put("id", i);   //id
                networkCardMap.put("netcd_no", i);   //������ϵͳ�е�����
                networkCardMap.put("netcd_name", devices[i].name); //������
                networkCardMap.put("netcd_description", devices[i].description); //������
                NetworkInterfaceAddress[] addresses = devices[i].addresses;
                networkCardMap.put("netcd_datalink_name", devices[i].datalink_name); //������·����
                networkCardMap.put("netcd_datalink_description", devices[i].datalink_description); //������·����
                for (int j = 0; j < addresses.length; j++) {
                    if(j == 0) {
                        networkCardMap.put("netcd_Iipv6", addresses[j].address.toString());   //ipv6
                    } else if(j == 1) {
                    	if(JSON.toJSONString(addresses[j]).contains("broadcast")) {
                            networkCardMap.put("netcd_ipv4", addresses[j].address.toString()); //ipv4
                            networkCardMap.put("netcd_broadcast", addresses[j].broadcast.toString()); //�㲥
                            networkCardMap.put("netcd_subnet", addresses[j].subnet.toString()); //��������
                    	} else {
                    		networkCardMap.put("netcd_Iipv6", addresses[j].address.toString());   //ipv6
                    	}
                    }
                }
                int length = devices[i].mac_address.length;  
                int count = 1; 
                StringBuilder sb = new StringBuilder("");
                for (byte b : devices[i].mac_address) {  
                    sb.append(Integer.toHexString(b & 0xff));
                    if(count++ != length) 
                        sb.append(":");
                }
                networkCardMap.put("netcd_mac", sb.toString());   //mac��ַ
                //�����е��豸��Ϣ���뵽
                networkCardMap.put("dev", devices[i]);
                System.out.println(JSON.toJSON(networkCardMap));
                list.add(networkCardMap);
            }
            return list;
        }catch(Exception e){
            e.printStackTrace();
        }
        System.out.println(JSON.toJSONString(list));
        return list;
    }
    
	@Override
	public void receivePacket(Packet packet) {
		if(NetFetcher.totalPack == 0) {
			Capture.jpcapCaptor.breakLoop();
			return;
		}
		if(NetFetcher.totalPack == -1) {
			NetFetcher.isCaptureing = true;
//			Capture.jpcapCaptor.breakLoop();
		} else {
			if(NetFetcher.currentPack < NetFetcher.totalPack) {
				NetFetcher.isCaptureing = true;
				NetFetcher.currentPack++;
			}else {
				NetFetcher.currentPack = 0;
				NetFetcher.isCaptureing = false;
//				System.out.println("NetFetcher.currentPack" + NetFetcher.currentPack);
//				System.out.println("NetFetcher.totalPack" + NetFetcher.totalPack);
			}
		}
		
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
            infoMap.put("SourcePort", String.valueOf("�޶˿ں�"));
            
            infoMap.put("SourceMacAddr", getMacInfo(datalink.src_mac));
            infoMap.put("TargetIp", icmpPacket.dst_ip.getHostAddress());
            infoMap.put("TargetPort", String.valueOf("�޶˿ں�"));
            infoMap.put("TargetMacAddr", getMacInfo(datalink.dst_mac));
        }
        arrayList.add(JSON.toJSONString(infoMap));
        System.out.print("ץ������");
        System.out.println(JSON.toJSONString(infoMap));
        System.out.println("NetFetcher.isCaptureing" + NetFetcher.isCaptureing);
//        try {
//            CatchDataToCache catchDataToCache = new CatchDataToCacheImpl();
//            catchDataToCache.setInfoToCache(infoMap);
//        } catch (Exception e) {
//            log.info("ץȡ����װ�뻺��ʱ �����쳣�����飺" + e);
//            jpcap.brea)kLoop();
//            if(jpcap != null) {
//                jpcap.close();
//            }
//        }
	}
	/*
	 * ���ݰ���Ϣ
	 */
	public static String[] getInfoArr() {
		int len = arrayList.size();
		String infoArr[] = new String[len];
		for(int i = 0; i < len; i++) {
			infoArr[i] = arrayList.get(i);
		}
//		if(NetFetcher.totalPack != -1) {
//			arrayList.clear();
//		}
//		NetFetcher.isCaptureing = false;
//		NetFetcher.currentPack = 0;
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
