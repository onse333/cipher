package com.test.util;

public class Validator {

	/**
	 * 
	 * ���ڿ��� null�϶� ""�� �����Ѵ�.
	 * 
	 * @param obj
	 * @return
	 */
	public static String nvl(Object obj) {
		return nvl(obj, "");
	}

	/**
	 * ���ڿ��� null�϶� ""�� �����Ѵ�.
	 * 
	 * @param obj
	 * @param ifNull
	 * @return
	 */
	public static String nvl(Object obj, String ifNull) {
		return (obj != null) ? obj.toString() : ifNull;
	}

}
