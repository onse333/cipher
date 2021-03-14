package com.test.example;
import java.util.HashMap;
import java.util.Map;

import com.test.cipher.CipherUtil;
import com.test.util.FileUtil;

public class Test
{
  public static void main(String[] args)throws Exception{
    String plainData = "xid|2019080514025975811681199489999999999999||eci|12345678901234567890123456789012345678901234567890||cavv|12345678901234567890123456789012345678901234567890||cardNum|9999888877772222||year|20220505";
    Map<String, Object> planDataMap = new HashMap<String, Object>();
    planDataMap.put("xid", "2019080514025975811681199489999999999999");
    planDataMap.put("eci", "12345678901234567890123456789012345678901234567890");
    planDataMap.put("cavv", "12345678901234567890123456789012345678901234567890");
    planDataMap.put("cardNum", "9999888877772222");
    planDataMap.put("year", "20220505");
    
    Map<String, Object> addInfo = new HashMap<String, Object>();
    addInfo.put("Issuer_code", "04");
    addInfo.put("Mon_installment", "B003");
    addInfo.put("Card_point", "00;11111111");
    
    String sessionPrivPath = "C:/Cipher/secret_private.pem";
    String sessionPubPath = "C:/Cipher/secret_public.pem";
    String signPrivPath = "C:/Cipher/sign_private.pem";
    String signPubPath = "C:/Cipher/sign_public.pem";
    
    CipherUtil cipher = new CipherUtil();
    
    cipher.init(
        FileUtil.readStringFromFileName(sessionPrivPath),
        FileUtil.readStringFromFileName(sessionPubPath),
        FileUtil.readStringFromFileName(signPrivPath),
        FileUtil.readStringFromFileName(signPubPath));

    String result[] = cipher.encryptData(planDataMap);
    String r5 = cipher.encryptDataForExtendInfo(addInfo);
    
    cipher.decrypt(result[0], result[1], result[2], result[3]);

    System.out.println(plainData);
    
    Map<String ,Object> resultMap = cipher.decrypt(result[0], result[1], result[2], result[3]);
    System.out.println(cipher.makeString(resultMap));
    
    Map<String ,Object> resultMap2 = cipher.decrypt(result[0], result[1], result[2], result[3], r5);
    System.out.println(cipher.makeString(resultMap2));
    
  }
}