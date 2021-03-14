package com.test.util;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;

public class FileUtil {
  
  public static String readStringFromFileName(String fileName) throws FileNotFoundException, IOException {
    String returnVal = null;
    BufferedReader br = null;

    try {
      br = new BufferedReader(new FileReader(fileName));
      StringBuffer sbf = new StringBuffer();
      String tempString = null;

      while((tempString = br.readLine()) != null) {
        sbf.append(tempString);
      }

      returnVal = sbf.toString();
      return returnVal;
    } catch (FileNotFoundException fe) {
      throw new FileNotFoundException("������ ã�� �� �����ϴ�.");
    } catch (IOException ie) {
      throw new IOException("������ �д� �� ����� ������ �߻��Ͽ����ϴ�.");
    } finally {
      if (br != null) {
        br.close();
      }
    }
  }
  
  public static byte[] readBytesFromFileName(String fileName) throws IOException {
    FileInputStream fis = new FileInputStream(fileName);
    byte[] byteArr = null;

    try {
      byteArr = readBytesFromStream(fis);
    } catch (IOException e) {} 
    finally {
      if (fis != null) {
        fis.close();
      }
    }
    return byteArr;
  }
  
  private static byte[] readBytesFromStream(InputStream is) throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream(10240);
    byte[] byteArr = new byte[10240];

    while(true) {
      int pos = is.read(byteArr);
      if (pos == -1) {
        return bos.toByteArray();
      }

      bos.write(byteArr, 0, pos);
    }
  }
}
