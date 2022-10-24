package com.secureworks.burp.prt;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

@SuppressWarnings("deprecation")
public abstract class PRTUtils {
	public enum CryptoCounterMode {
		GCM,
		CBC
	}

	public static byte[] getJWSPayload(byte[] JWS) throws Exception{
		
		String jws = new String(JWS,StandardCharsets.UTF_8); 
				
		return getJWSPayload(jws);
	}
	
	public static byte[] getJWSPayload(String JWS) throws Exception{
		
		String[] parts = JWS.split("[.]");
		// JWS should have three parts, but Java split omits empty values :(
		if(parts.length == 3 || parts.length == 2)
		{
			return Base64.getUrlDecoder().decode(parts[1]);
		}
		else
		{
			throw new Exception("JWS must have three parts.");
		}
	}
	
	public static byte[] deriveCEK(JWE JWE, byte[] sessionKey) throws Exception{
		if(JWE.getHeader().getCtx() == null)
		{
			throw new Exception("JWE is missing ctx.");
		}
		byte[] ctx = Base64.getDecoder().decode(JWE.getHeader().getCtx());
		byte[] label = "AzureAD-SecureConversation".getBytes(StandardCharsets.UTF_8);
		byte[] buffer = new byte[4 + label.length + 1 + ctx.length + 4];

		buffer[3] = 1; // version
		buffer[buffer.length - 2] = 1; // lenght in bits = 0x100 = 32 bytes
		System.arraycopy(label, 0, buffer, 4, label.length); // label
		System.arraycopy(ctx, 0, buffer, 4 + label.length + 1, ctx.length);

		HMac mac = new HMac(new  SHA256Digest());
		mac.init(new KeyParameter(sessionKey));
		mac.update(buffer,0,buffer.length);
		byte[] derivedKey = new byte[mac.getMacSize()];
		mac.doFinal(derivedKey,0);

		return derivedKey;
	}

	public static byte[] decryptCEK(JWE JWE, RSAPrivateKey rsa) throws Exception
	{
		try {
			AsymmetricBlockCipher engine = new RSAEngine();

			OAEPEncoding cipher = new OAEPEncoding(engine);
			
			RSAPrivateCrtKeyParameters keyParameters = new RSAPrivateCrtKeyParameters(rsa.getModulus(), rsa.getPublicExponent(), rsa.getPrivateExponent(), rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(), rsa.getExponent2(), rsa.getCoefficient());
			
			cipher.init(false, keyParameters);
			byte[] keyBytes = JWE.getKey();
			return cipher.processBlock(keyBytes, 0, keyBytes.length);
		}
		catch(InvalidCipherTextException e) {
			throw new Exception("Could not decrypt CEK. Wrong transport key?");
		}
	}
	
	private static byte[] decryptCBC(byte[] cipherText, byte[] key, byte[] iv) throws DataLengthException, IllegalStateException, InvalidCipherTextException
	{
        // Create & init CBC block cipher.
		KeyParameter keyParameter = new KeyParameter(key);
        CBCBlockCipher CBCBlockCipher = new CBCBlockCipher(new AESFastEngine());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(CBCBlockCipher);
        cipher.init(false, new ParametersWithIV(keyParameter,iv));
    
        // Create an a array for the decrypted data
        byte[] decData = new byte[cipher.getOutputSize(cipherText.length)];

        // Decrypt the data
        int res = cipher.processBytes(cipherText, 0, cipherText.length, decData, 0);
        res = cipher.doFinal(decData, res);
        
        return decData;
	}
	
	private static byte[] decryptGCM(byte[] cipherText, byte[] key, byte[] iv) throws DataLengthException, IllegalStateException, InvalidCipherTextException
	{
        // Create & init GCM block cipher.
		KeyParameter keyParameter = new KeyParameter(key);
        AEADParameters AEADParameters = new AEADParameters(keyParameter,128,iv);
        GCMBlockCipher cipher = new GCMBlockCipher(new AESFastEngine());
        cipher.init(false, AEADParameters);
    
        // Create an a array for the decrypted data
        byte[] decData = new byte[cipher.getOutputSize(cipherText.length)];

        // Decrypt the data
        int res = cipher.processBytes(cipherText, 0, cipherText.length, decData, 0);
        res = cipher.doFinal(decData, res);
        
        return decData;
	}
	
	public static byte[] decryptData(JWE JWE, byte[] CEK, CryptoCounterMode mode)
    {
        byte[] decData = null;
        switch (mode)
        {
            case CBC:
            	// This data is incorrectly encrypted with A256CBC.
            	try
            	{
            		decData = decryptCBC(JWE.getCipherText(), CEK, JWE.getIv());
            	}
            	catch(Exception e)
            	{
            		throw new RuntimeException("Unable to decrypt. Invalid Session Key?");
            	}
                
                break;

            case GCM:
                //Append Tag to Encrypted data
                byte[] encData = new byte[JWE.getCipherText().length + JWE.getTag().length];
                
                System.arraycopy(JWE.getCipherText(),0,encData,0,JWE.getCipherText().length);
                System.arraycopy(JWE.getTag(),0,encData,JWE.getCipherText().length,JWE.getTag().length);
                
                // This data is correctly encrypted with A256GCM.
                try
            	{
                	decData = decryptGCM(encData, CEK, JWE.getIv());
            	}
            	catch(Exception e)
            	{
            		throw new RuntimeException("Unable to decrypt. Invalid key?");
            	}
                
                break;
        }
        return decData;
    }
	
	public static JWEData decryptJWE(String JWE, String transPortKeyFileName, String sessionKey) throws Exception
    {
        if(transPortKeyFileName == null && sessionKey == null)
        {
            throw new RuntimeException("Transport Key Filename or Session Key must be provided.");
        }

        JWE objJWE = parseJWE(JWE);

        if (!objJWE.getHeader().getEnc().equals("A256GCM"))
        {
            throw new RuntimeException("Unsupported encryption algorithm");
        }

        JWEData jweData = null;


        if (transPortKeyFileName != null)
        {
            String PEM = new String(Files.readAllBytes(Paths.get(transPortKeyFileName)));
            PemReader reader = new PemReader(new StringReader(PEM));
            PemObject pem = reader.readPemObject();
            RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
            
            jweData = new JWEData(decryptCEK(objJWE, rsa));
        }
        else
        {
            jweData = new JWEData( deriveCEK(objJWE, Base64.getDecoder().decode(sessionKey)));
        }
        
        if (objJWE.getCipherText() != null)
        {
            switch(objJWE.getHeader().getAlg())
            {
                case "dir":
                    jweData.setData(decryptData(objJWE, jweData.getCek(), CryptoCounterMode.CBC));
                    break;
                case "RSA-OAEP":
                    jweData.setData(decryptData(objJWE, jweData.getCek(), CryptoCounterMode.GCM));
                    break;
                default:
                    throw new RuntimeException("Unsupported algorithm");
            }

        }

        return jweData;
    }
	
	public static JWE parseJWE(String JWE) throws Exception
    {
        String[] parts = JWE.split("[.]");
        if(parts.length != 5 && parts.length != 4) // Split removes the trailing empty string :(
        {
            throw new Exception("JWE must have five parts.");
        }
        
        byte[] header = Base64.getUrlDecoder().decode(parts[0]);
        byte[] key = Base64.getUrlDecoder().decode(parts[1]);
        byte[] iv = Base64.getUrlDecoder().decode(parts[2]);
        byte[] cipherText = Base64.getUrlDecoder().decode(parts[3]);
        byte[] tag = null;
        if(parts.length == 5)
        	tag = Base64.getUrlDecoder().decode(parts[4]);

        return new JWE(header, key, iv, cipherText, tag);

    }
}
