package com.test.cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.StringTokenizer;

import javax.crypto.Cipher;

import com.test.util.Base64;

public class RSACipher {

  private static final String PUBLIC_START = "-----BEGIN PUBLIC KEY-----";
  private static final String PUBLIC_END = "-----END PUBLIC KEY-----";
  private static final String PRIVATE_START = "-----BEGIN RSA PRIVATE-----";
  private static final String PRIVATE_END = "-----END RSA PRIVATE-----";
  
  private String charSet = "MS949"; 
  
  public RSACipher(String charSet) {
    this.charSet = charSet;
  }
  
  public PublicKey getPublicKey(String publicKey) throws Exception{
    KeyFactory factory = KeyFactory.getInstance("RSA");
    byte[] content = Base64.decode(substring(delCRLF(publicKey), PUBLIC_START, PUBLIC_END));
    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
    PublicKey pub  = factory.generatePublic(pubKeySpec);
    
    return pub;
  }
  
  public PrivateKey getPrivateKey(String privateKey) throws Exception{
    PrivateKey priv = null;
    KeyFactory rkeyFactory = KeyFactory.getInstance("RSA");
    byte[] content = Base64.decode(substring(delCRLF(privateKey), PRIVATE_START, PRIVATE_END));
    PKCS8EncodedKeySpec rkeySpec = new PKCS8EncodedKeySpec(content);
    priv = rkeyFactory.generatePrivate(rkeySpec);
    
    return priv;
  }
  
  /**
   * RSA 암호화 수행
   * @param plainString : 암호화 대상 text, publicKey : 공개키(PEM)
   * @return 암호화 된 데이터
   */
  public String encrypt(String plainString, String publicKey) throws Exception{
    String returnVal = "";
    
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    KeyFactory factory = KeyFactory.getInstance("RSA");
    byte[] content = Base64.decode(substring(delCRLF(publicKey), PUBLIC_START, PUBLIC_END));
    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
    PublicKey pub  = factory.generatePublic(pubKeySpec);
    byte[] input = plainString.getBytes();
    cipher.init(Cipher.ENCRYPT_MODE, pub);
    byte[] cipherText = cipher.doFinal(input);
    
    returnVal = byteArrayToHex(cipherText); 
    returnVal = Base64.encodeBytes(returnVal.getBytes(charSet));
    
    return returnVal;
  }
  /**
   * RSA 복호화 수행
   * @param encodedString : 복호화 대상 text, privateKey : 개인키(PEM)
   * @return 복호화 된 데이터
   */
  public String decrypt(String encodedString, String privateKey) throws Exception{
    byte[] encodedBytes = Base64.decode(encodedString);
    String decryptString = "";
    String encryptText = new String(encodedBytes, charSet);
    KeyFactory rkeyFactory = null;
    PrivateKey priv = null;
    rkeyFactory = KeyFactory.getInstance("RSA");
    byte[] content = Base64.decode(substring(delCRLF(privateKey), PRIVATE_START, PRIVATE_END));
    PKCS8EncodedKeySpec rkeySpec = new PKCS8EncodedKeySpec(content);
    priv = rkeyFactory.generatePrivate(rkeySpec);
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    
    byte[] encryptedBytes = hexToByteArray(encryptText);
    cipher.init(Cipher.DECRYPT_MODE, priv);
    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
    decryptString = new String(decryptedBytes, charSet);
    return decryptString;
  }

  private String byteArrayToHex(byte[] ba) {
    if (ba == null || ba.length == 0) {
      return null;
    }
    StringBuffer sb = new StringBuffer(ba.length * 2);
    String hexNumber;
    for (int x = 0; x < ba.length; x++) {
      hexNumber = "0" + Integer.toHexString(0xff & ba[x]);

      sb.append(hexNumber.substring(hexNumber.length() - 2));
    }
    return sb.toString();
  }

  private byte[] hexToByteArray(String hex) {
    if (hex == null || hex.length() % 2 != 0) {
      return new byte[] {};
    }

    byte[] bytes = new byte[hex.length() / 2];
    for (int i = 0; i < hex.length(); i += 2) {
      byte value = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
      bytes[(int) Math.floor(i / 2)] = value;
    }
    return bytes;
  }
  
  public String substring(String targetString, String startString, String endString){
    return new StringBuffer(targetString).substring(startString.length(), targetString.length() - endString.length());
  }
  
  public String delCRLF(String paramString){
    StringBuffer localStringBuffer = new StringBuffer();
    StringTokenizer localStringTokenizer = new StringTokenizer(paramString, "\n\r");
    while (localStringTokenizer.hasMoreTokens()) {
      localStringBuffer.append(localStringTokenizer.nextToken());
    }
    return localStringBuffer.toString();
  }
}
