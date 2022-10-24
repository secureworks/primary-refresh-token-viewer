package com.secureworks.burp.prt;

public class JWEData {
	private byte[] cek;
	private byte[] data;
	
	public byte[] getCek() {
		return cek;
	}

	public void setCek(byte[] cek) {
		this.cek = cek;
	}

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public JWEData(byte[] CEK)
	{
		this(CEK, null);
	}
	
	public JWEData(byte[] CEK, byte[] data)
	{
		this.cek = CEK;
		this.data = data;
	}
}
