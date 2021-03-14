package com.test.cipher;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.test.util.Base64;


public class CipherUtil
{
  
  public static final String PIPE_LINE_DELIMETER = "|";
  private String secretPrivate; 
  private String secretPublic; 
  private String signPrivate; 
  private String signPublic; 
  private String charSet = "MS949"; 
  
  /**
   * 초기화 수행
   * @param String secretPrivKey, String secretPubKey, String signPrivKey, String signPubKey
   * @return void
   */
  public void init(String secretPrivKey, String secretPubKey, String signPrivKey, String signPubKey){
    secretPrivate = secretPrivKey;
    secretPublic = secretPubKey;
    signPrivate = signPrivKey;
    signPublic = signPubKey;
  }
  
  public void setEncoding(String val){
    charSet = val;
  }
  
  /**
   * 초기화 수행
   * @param String String secretPubKey, String signPrivKey, String signPubKey
   * @return void
   */
  public void initForEncrypt(String secretPubKey, String signPrivKey, String signPubKey){
    secretPublic = secretPubKey;
    signPrivate = signPrivKey;
    signPublic = signPubKey;
  }
  
  /**
   * 초기화 수행
   * @param String secretPrivKey
   * @return void
   */
  public void initForDecrypt(String secretPrivKey) {
    secretPrivate = secretPrivKey;
  }
  
  public String encryptDataForExtendInfo(Map<String, Object> map)throws Exception{
    String originalMsg = makeString(map);
    RSACipher rsaCipher = new RSACipher(charSet);
    String r5 = rsaCipher.encrypt(originalMsg, secretPublic);
    
    return r5;
  }
  
  /**
   * 암호화 수행
   * @param map : 평문데이터
   * @return 암호화 된 데이터 array
   */
  public String[] encryptData(Map<String, Object> map)throws Exception{
    
    String originalMsg = makeString(map);
    return encryptData(originalMsg);
  }
  
  /**
   * 암호화 수행
   * @param plainData : 평문데이터
   * @return 암호화 된 데이터 array
   */
  public String[] encryptData(String plainData)throws Exception{

    byte[] pbData = plainData.getBytes(charSet);
    RSACipher rsaCipher = new RSACipher(charSet);
    
    byte[] pbUserKey = getRandByte();
    String pbUserKeyString = Base64.encodeBytes(pbUserKey);
    String rsaPbUserKeyString = rsaCipher.encrypt(pbUserKeyString, secretPublic);
    byte[] bszIV = Base64.decode(initialVector);
    
    byte pbCipher[]   = Seed.SEED_CBC_Encrypt(pbUserKey, bszIV, pbData, 0, pbData.length);
    RSAPrivateKey priv = (RSAPrivateKey)rsaCipher.getPrivateKey(signPrivate);
    RSAPublicKey pub = (RSAPublicKey)rsaCipher.getPublicKey(signPublic);
    
    byte[] encodedPublicKey = pub.getEncoded();

    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(priv);
    signature.update(pbData);
    byte[] hashVal = signature.sign();
    
    String[] returnVal = new String[4];
    
    returnVal[0] = rsaPbUserKeyString;  //secret key
    returnVal[1] = Base64.encodeBytes(pbCipher);  // enc val
    returnVal[2] = Base64.encodeBytes(encodedPublicKey); //sign pub
    returnVal[3] = Base64.encodeBytes(hashVal); // enc hash val
    return returnVal;
  }
  
  /**
   * 복호화 수행
   * @param r1 : 암호화 세션키, r2 : 암호화 된 값, r3 : 공개키, r4 : 전자서명값
   * @return 복호화 된 데이터(Map)
   */
  public Map<String, Object> decrypt(String r1, String r2, String r3, String r4)throws Exception{
    String rsaPbUserKeyString = r1;
    String cipherText = r2;
    RSACipher rsaCipher = new RSACipher(charSet);
    String rsaPbUserKey = rsaCipher.decrypt(rsaPbUserKeyString, secretPrivate);
    byte[] rsaPbUserKeyByte = Base64.decode(rsaPbUserKey);
    byte[] rsaBszIVByte = Base64.decode(initialVector);
    byte[] pbCipher = Base64.decode(cipherText);
    
    byte[] resultByte = Seed.SEED_CBC_Decrypt(rsaPbUserKeyByte, rsaBszIVByte, pbCipher, 0, pbCipher.length);
    String result = new String(resultByte, charSet);
    Signature signature = Signature.getInstance("SHA256withRSA");
    
    PublicKey sigPub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decode(r3)));
    
    signature.initVerify(sigPub);
    signature.update(resultByte);
    
    boolean sigResult = signature.verify(Base64.decode(r4));
    
    if(!sigResult) {
      throw new Exception("전자서명 검증 실패");
    }
    
    Map<String, Object> returnMap = makeMap(result);
    
    return returnMap;
  }
  /**
   * 복호화 수행
   * @param r1 : 암호화 세션키, r2 : 암호화 된 값, r3 : 공개키, r4 : 전자서명값, r5 : 추가 데이터
   * @return 복호화 된 데이터(Map)
   */
  public Map<String, Object> decrypt(String r1, String r2, String r3, String r4, String r5)throws Exception{
    
    Map<String, Object> dataMap = decrypt(r1,r2,r3,r4);
    Map<String, Object> extendInfo = decryptDataForExtendInfo(r5);
    return combineData(dataMap, extendInfo);
  }
  
  public Map<String, Object> decryptDataForExtendInfo(String r5)throws Exception{
    RSACipher rsaCipher = new RSACipher(charSet);
    String decString = rsaCipher.decrypt(r5, secretPrivate);
    
    return makeMap(decString);
  }
  
  public Map<String, Object> makeMap(String string){
    Map<String, Object> returnMap = new HashMap<String, Object>(); 
    String[] arr0 = string.split("\\|\\|"); 
    
    for (String element : arr0 ) {
      String[] arr1 = element.split("\\|");
      String key = arr1[0];
      String value = arr1[1];
      returnMap.put(key, value);
    }
    
    return returnMap;  
   }
  
  public String makeString(Map<String, Object> map){
    StringBuffer sb = new StringBuffer();

    Iterator<String> iterator = map.keySet().iterator();
    while (iterator.hasNext()){
      String key = iterator.next();
      Object obj = map.get(key);
      if ((obj instanceof String)){
        String value = (String)obj;
        sb.append(key);
        sb.append(PIPE_LINE_DELIMETER);
        sb.append(value);
        sb.append(PIPE_LINE_DELIMETER);
        sb.append(PIPE_LINE_DELIMETER);
      } else{
        String[] values = (String[]) map.get(key);
        if (values != null){
          for (int i = 0; i < values.length; i++){
            String value = values[i];
            if (value == null) {
              value = "";
            }
            sb.append(key);
            sb.append(PIPE_LINE_DELIMETER);
            sb.append(value);
            sb.append(PIPE_LINE_DELIMETER);
            sb.append(PIPE_LINE_DELIMETER);
          }
        }
      }
    }
    return sb.toString();
  }

  private static final String initialVector = "test=="; // iv 생성하여 hardcoding
  
  private byte[] getRandByte() throws Exception{    
    SecureRandom random = new SecureRandom();
    byte[] values = new byte[16];
    random.nextBytes(values);
    return values;
  }

  private Map<String, Object> combineData(Map<String, Object> parameters1, Map<String, Object> parameters2) {

    Map<String, Object> joinedParameters = new HashMap<String, Object>();
    joinedParameters.putAll(parameters1);
    joinedParameters.putAll(parameters2);

    return joinedParameters;
  }
}