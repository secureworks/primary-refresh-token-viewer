using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace Secureworks
{
    public class SessionKeyJWE
    {
        private string session_key_jwe;

        public string Session_key_jwe { get => session_key_jwe; set => session_key_jwe = value; }
    }
    public class JWEData
    {
        private byte[] cek;
        private byte[] data;

        public JWEData(byte[] CEK, byte[] data = null)
        {
            this.cek  = CEK;
            this.data = data;
        }

        public byte[] CEK { get => cek; set => cek = value; }
        public byte[] Data { get => data; set => data = value; }
    }
    public class JWEHeader
    {
        private string ctx;
        private string alg;
        private string enc;
        private string kdf_ver;

        public string Ctx { get => ctx; set => ctx = value; }
        public string Alg { get => alg; set => alg = value; }
        public string Enc { get => enc; set => enc = value; }
        public string Kdf_ver { get => kdf_ver; set => kdf_ver = value; }
    }
    public class JWE
    {
        private JWEHeader header;
        private byte[] key;
        private byte[] iv;
        private byte[] cipherText;
        private byte[] tag;

        public byte[] Key { get => key; set => key = value; }
        public byte[] Iv { get => iv; set => iv = value; }
        public byte[] CipherText { get => cipherText; set => cipherText = value; }
        public byte[] Tag { get => tag; set => tag = value; }
        public JWEHeader Header { get => header; set => header = value; }

        public JWE(byte[] header, byte[] key, byte[] iv, byte[] cipherText, byte[] tag) : this(new JWEHeader(), key, iv, cipherText, tag)
        {
            string strHeader = Encoding.UTF8.GetString(header);

            this.header = JsonConvert.DeserializeObject<JWEHeader>(strHeader);

        }

        public JWE(byte[][] jwe): this(jwe[0], jwe[1], jwe[2], jwe[3], jwe[4])
        {

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
    public static class PRTUtils
    {
        public enum CryptoCounterMode
        {
            GCM, CBC
        }

        public static byte[] DeriveCEK(JWE JWE, byte[] sessionKey)
        {
            if(String.IsNullOrEmpty(JWE.Header.Ctx))
            {
                throw new Exception("JWE is missing ctx.");
            }
            byte[] ctx = PRTUtils.ConvertB64ToByteArray(JWE.Header.Ctx);
            byte[] label = System.Text.Encoding.UTF8.GetBytes("AzureAD-SecureConversation");
            byte[] buffer = new byte[4 + label.Length + 1 + ctx.Length + 4];

            buffer[3] = 1; // version
            buffer[buffer.Length - 2] = 1; // lenght in bits = 0x100 = 32 bytes
            Array.Copy(label, 0, buffer, 4, label.Length); // label
            Array.Copy(ctx, 0, buffer, 4 + label.Length + 1, ctx.Length);

            System.Security.Cryptography.HMACSHA256 hmacSha = new System.Security.Cryptography.HMACSHA256(sessionKey);
            byte[] derivedKey = hmacSha.ComputeHash(buffer);
            hmacSha.Dispose();

            return derivedKey;
        }
        public static byte[] DecryptCEK(JWE JWE, RSA RSA)
        {
            byte[] CEK = new System.Security.Cryptography.RSAOAEPKeyExchangeDeformatter(RSA).DecryptKeyExchange(JWE.Key);

            return CEK;
        }

        public static byte[] DecryptData(JWE JWE, byte[] CEK, CryptoCounterMode mode)
        {
            byte[] decData = null;
            switch (mode)
            {
                case CryptoCounterMode.CBC:
                    System.Security.Cryptography.AesCryptoServiceProvider provider = new System.Security.Cryptography.AesCryptoServiceProvider();
                    provider.Key = CEK;
                    provider.IV = JWE.Iv;

                    System.IO.MemoryStream buffer = new System.IO.MemoryStream();
                    System.Security.Cryptography.CryptoStream cryptoStream = new System.Security.Cryptography.CryptoStream(buffer, provider.CreateDecryptor(), System.Security.Cryptography.CryptoStreamMode.Write);
                    cryptoStream.Write(JWE.CipherText, 0, JWE.CipherText.Count());
                    cryptoStream.FlushFinalBlock();

                    decData = buffer.ToArray();

                    provider.Dispose();
                    cryptoStream.Dispose();
                    break;

                case CryptoCounterMode.GCM:
                    break;
            }
            return decData;
        }

        public static JWEData DecryptJWE(string JWE, string transPortKeyFileName = null, string sessionKey = null)
        {
            if(String.IsNullOrEmpty(transPortKeyFileName) & String.IsNullOrEmpty(sessionKey))
            {
                throw new Exception("Transport Key Filename or Session Key must be provided.");
            }

            JWE objJWE = ParseJWE(JWE);

            if (!objJWE.Header.Enc.Equals("A256GCM"))
            {
                throw new Exception("Unsupported encryption algorithm");
            }

            JWEData jweData;


            if (!String.IsNullOrEmpty(transPortKeyFileName))
            {
                string PEM = System.IO.File.ReadAllText(transPortKeyFileName);
                Org.BouncyCastle.OpenSsl.PemReader reader = new Org.BouncyCastle.OpenSsl.PemReader(new System.IO.StringReader(PEM));
                Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keys = (Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)reader.ReadObject();
                RSAParameters RSAParameters = Org.BouncyCastle.Security.DotNetUtilities.ToRSAParameters((Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)keys.Private);

                RSA RSA = RSA.Create(RSAParameters);

                jweData = new JWEData(DecryptCEK(objJWE, RSA));
            }
            else
            {
                jweData = new JWEData( DeriveCEK(objJWE, PRTUtils.ConvertB64ToByteArray(sessionKey)));
            }

            if (objJWE.CipherText != null)
            {
                switch(objJWE.Header.Alg)
                {
                    case "dir":
                        jweData.Data = DecryptData(objJWE, jweData.CEK, CryptoCounterMode.CBC);
                        break;
                    case "RSA-OAEP":
                        jweData.Data = DecryptData(objJWE, jweData.CEK, CryptoCounterMode.GCM);
                        break;
                    default:
                        throw new Exception("Unsupported algorithm");
                }

            }

            return jweData;
        }


        public static byte[] ConvertB64ToByteArray(string b64)
        {
            if(String.IsNullOrEmpty(b64))
            {
                return null;
            }

            b64 = b64.Replace('_', '/').Replace('-', '+').TrimEnd(new char[] { (char)0, '=' });
            while (b64.Length % 4 != 0)
            {
                b64 += '=';
            }

            return Convert.FromBase64String(b64);
        }



        public static JWE ParseJWE(string JWE)
        {
            List<byte[]> retVal = new List<byte[]>();

            string[] parts = JWE.Split('.');
            if(parts.Length != 5)
            {
                throw new Exception("JWE must have five parts.");
            }
            foreach(string part in parts)
            {
                retVal.Add(PRTUtils.ConvertB64ToByteArray(part));
            };

            return new JWE(retVal.ToArray<byte[]>());

        }
    }
}
