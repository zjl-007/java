package com;

import com.alibaba.fastjson.JSON;

//package com.cn.test;
public class PathToTree {
	public static Capture capture = new Capture();
	public static Thread captureThread =  null;
	public static void main(String[] args) {
		System.out.println("ok`````");
//		PathToTree.startCapture(0, 10, "ip");
//		String[] res = PathToTree.getCaptureResult();
//		while(res.length <= 20) {
//			res = PathToTree.getCaptureResult();
//			System.out.println(res.length);
//		}
//		PathToTree.stopCapture();
////		System.out.println(res);
//		
//		System.out.println(capture.getCaptureState());
    }
	
	public static boolean getCaptureState() {
		return capture.getCaptureState();
	}
	public static String startCapture(int index, int count, String content) {
		if(NetFetcher.isCaptureing) {
			return "正在抓包中,请勿重复抓包！";
		}
		NetFetcher.isCaptureing = true;
		Runnable runnable = new Runnable() {
            @Override
            public void run() {
				capture.startCapture(index, count, content);
            }
        };
        captureThread = new Thread(runnable);
        captureThread.start();
        return "开始抓包";
	}
	
	public static void stopCapture() {
		capture.stopCapture(captureThread);
	}
	
	public static String[] getCaptureResult() {
		return capture.getCpatureInfo();
	}
	public static String[] getDevicesInfo() {
		return capture.getDevicesInfo();
	}
}
	
