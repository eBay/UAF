package org.ebayopensource.fido.uaf.crypto;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;


public class Asn1Test {

	@Test
	public void test() throws IOException {
		String signatureB64 = "MEUCIAbY7xI6QfBlurbgIax85rB583xy37CdFadbvR9QJJAHAiEA8REEB2ouX34TYPqeSDQigJTKg3GmeS1sx6_5BJjtT6U";
		BigInteger[] bigIntegerArray = Asn1.decodeToBigIntegerArray(Base64.decodeBase64(signatureB64));
		byte[] encoded = Asn1.getEncoded(bigIntegerArray);
		assertTrue(signatureB64.equals(Base64.encodeBase64URLSafeString(encoded)));
	}
	
	@Test
	public void rick() throws IOException {
		String signatureB64 = "MEQCIAwtk4DStr2MqkrAlOVG+nyQxbS6tnBpVi7OcKCm8/5lAiBjVsv+b+7nI/306iNHrso/ruOaxY8IJy3jw2/zr17JEQ==";
		BigInteger[] bigIntegerArray = Asn1.decodeToBigIntegerArray(Base64.decodeBase64(signatureB64));
		byte[] encoded = Asn1.getEncoded(bigIntegerArray);
		String encodeBackToBase64 = Base64.encodeBase64String(encoded);
		assertTrue(signatureB64.equals(encodeBackToBase64));
	}

	@Test
	public void rickSafeURLEncoding() throws IOException {
		String signatureB64 = "MEQCIAwtk4DStr2MqkrAlOVG+nyQxbS6tnBpVi7OcKCm8/5lAiBjVsv+b+7nI/306iNHrso/ruOaxY8IJy3jw2/zr17JEQ==";
		String signatureB64Safe = "MEQCIAwtk4DStr2MqkrAlOVG-nyQxbS6tnBpVi7OcKCm8_5lAiBjVsv-b-7nI_306iNHrso_ruOaxY8IJy3jw2_zr17JEQ";
		BigInteger[] bigIntegerArray = Asn1.decodeToBigIntegerArray(Base64.decodeBase64(signatureB64));
		BigInteger[] bigIntegerArrayFromURLSafe = Asn1.decodeToBigIntegerArray(Base64.decodeBase64(signatureB64Safe));
		assertTrue(bigIntegerArray[0].equals(bigIntegerArrayFromURLSafe[0]));
		assertTrue(bigIntegerArray[1].equals(bigIntegerArrayFromURLSafe[1]));
	}	
}
