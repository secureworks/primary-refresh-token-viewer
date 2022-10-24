package com.secureworks.burp.prt;

import com.google.gson.Gson;

public class JWE {
	private JWEHeader header;
	public JWEHeader getHeader() {
		return header;
	}

	public void setHeader(JWEHeader header) {
		this.header = header;
	}

	public byte[] getKey() {
		return key;
	}

	public void setKey(byte[] key) {
		this.key = key;
	}

	public byte[] getIv() {
		return iv;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
	}

	public byte[] getCipherText() {
		return cipherText;
	}

	public void setCipherText(byte[] cipherText) {
		this.cipherText = cipherText;
	}

	public byte[] getTag() {
		return tag;
	}

	public void setTag(byte[] tag) {
		this.tag = tag;
	}
	private byte[] key;
    private byte[] iv;
    private byte[] cipherText;
    private byte[] tag;
    
    public JWE(byte[] header, byte[] key, byte[] iv, byte[] cipherText, byte[] tag) 
    {
    	this(new Gson().fromJson(new String(header), JWEHeader.class), key, iv, cipherText, tag);

    }

    public JWE(byte[][] jwe)
    {
    	this(jwe[0], jwe[1], jwe[2], jwe[3], jwe[4]);
    }
    public JWE(JWEHeader header, byte[] key, byte[] iv, byte[] cipherText, byte[] tag)
    {
        this.header = header;
        this.key = key;
        this.iv = iv;
        this.cipherText = cipherText;
        this.tag = tag;
    }

}
