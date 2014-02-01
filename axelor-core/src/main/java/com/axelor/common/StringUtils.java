package com.axelor.common;

/**
 * This class provides static helper methods for {@link String}.
 * 
 */
public final class StringUtils {

	/**
	 * Check whether the given string value is empty. The value is empty if null
	 * or length is 0.
	 * 
	 * @param value
	 *            the string value to test
	 * @return true if empty false otherwise
	 */
	public static boolean isEmpty(String value) {
		return value == null || value.length() == 0;
	}

	/**
	 * Check whether the given string value is blank. The value is blank if null
	 * or contains white spaces only.
	 * 
	 * @param value
	 *            the string value to test
	 * @return true if empty false otherwise
	 */
	public static boolean isBlank(String value) {
		if (isEmpty(value)) {
			return true;
		}
		for (int i = 0; i < value.length(); i++) {
			if (!Character.isWhitespace(value.charAt(i))) {
				return false;
			}
		}
		return true;
	}
}