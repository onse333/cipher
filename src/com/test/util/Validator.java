package com.test.util;

public class Validator {

	/**
	 * 
	 * 문자열이 null일때 ""를 리턴한다.
	 * 
	 * @param obj
	 * @return
	 */
	public static String nvl(Object obj) {
		return nvl(obj, "");
	}

	/**
	 * 문자열이 null일때 ""를 리턴한다.
	 * 
	 * @param obj
	 * @param ifNull
	 * @return
	 */
	public static String nvl(Object obj, String ifNull) {
		return (obj != null) ? obj.toString() : ifNull;
	}

}
