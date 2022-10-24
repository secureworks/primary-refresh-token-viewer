package com.secureworks.burp.prt;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;


public abstract class BurpUtils {
	
	public static int maxSize = 1024 * 20;
	
	public static byte[] getBody(byte[] content, int bodyOffset)
	{
		byte[] body = new byte[content.length - bodyOffset];
		System.arraycopy(content,bodyOffset,body,0,body.length);
		
		return body;
	}
	
	public static String getHeader(List<String> headers, String name)
	{
		for(String header : headers)
		{
			if(header.startsWith(name+": "))
			{
				return header.substring(name.length()+2);
			}
				
		}
		
		return null;
	}
	
	
	public static Map<String, String> parseJson(byte[] content, int bodyOffset)
	{
		byte[] body = getBody(content, bodyOffset);
		
		return parseJson(body);
	}
	
	public static Map<String, String> parseJson(byte[] body)
	{
		String json = new String(body,StandardCharsets.UTF_8);
		
		return parseJson(json);
	}
	
	@SuppressWarnings("unchecked")
	public static Map<String, String> parseJson(String json)
	{
		Gson gson = new Gson();
		
		// Need to strip null terminators from the end
		json = json.replace("\0", "");
		return (Map<String, String>)gson.fromJson(json, Map.class);
	}

	public static boolean isJson(List<String> headers)
	{
		for(String header : headers)
		{
			if(header.startsWith("Content-Type: application/json"))
				return true;
		}
		
		return false;
	}
	
	public static boolean hasBearer(List<String> headers)
	{
		for(String header : headers)
		{
			if(header.startsWith("Authorization: Bearer ") || header.startsWith("Authorization: aad "))
				return true;
		}
		
		return false;
	}
	
	public static boolean isJose(List<String> headers)
	{
		for(String header : headers)
		{
			if(header.startsWith("Content-Type: application/jose"))
				return true;
		}
		
		return false;
	}
	
	public static byte[] setContentType(byte[] data, String contentType)
	{
		String addHeader = "Content-Type: "+contentType;
		addHeader += "\r\n\r\n";
		byte[] newdata = new byte[addHeader.length() + data.length];
		
		System.arraycopy(addHeader.getBytes(StandardCharsets.US_ASCII),0,newdata,0,addHeader.length());
		System.arraycopy(data,0, newdata,addHeader.length(),data.length);
		
		return newdata;
	}
}
