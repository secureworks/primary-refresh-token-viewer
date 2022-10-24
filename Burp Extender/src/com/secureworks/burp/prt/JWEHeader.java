package com.secureworks.burp.prt;

public class JWEHeader {

	private String ctx;
    private String alg;
    private String enc;
    private String kdf_ver;
    
	public String getCtx() {
		return ctx;
	}
	public void setCtx(String ctx) {
		this.ctx = ctx;
	}
	public String getAlg() {
		return alg;
	}
	public void setAlg(String alg) {
		this.alg = alg;
	}
	public String getEnc() {
		return enc;
	}
	public void setEnc(String enc) {
		this.enc = enc;
	}
	public String getKdf_ver() {
		return kdf_ver;
	}
	public void setKdf_ver(String kdf_ver) {
		this.kdf_ver = kdf_ver;
	}
	
	/*public JWEHeader(byte[] header)
	{
		try {
			
			
			/*LinkedHashMap<String,String> json = (LinkedHashMap<String, String>) Json.parse(new StringReader(new String(header)));
			alg = json.get("alg");
			enc = json.get("enc");
			
			if(json.containsKey("ctx"))
				ctx = json.get("ctx");
			if(json.containsKey("kdf_ver"))
				kdf_ver = json.get("kdf_ver");
				

		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}*/
}
