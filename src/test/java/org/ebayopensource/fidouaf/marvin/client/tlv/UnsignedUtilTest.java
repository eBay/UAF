package org.ebayopensource.fidouaf.marvin.client.tlv;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

public class UnsignedUtilTest {

	@Test
	public void max_int() {
		int m = Integer.MAX_VALUE;
		byte[] mBytes = UnsignedUtil.encodeInt32(m);
		byte[] mBytesBigEndian = reverse (mBytes);
		BigInteger big = new BigInteger(mBytesBigEndian);
		assertTrue (big.intValue() == m);
	}
	
	@Test
	public void small_int() {
		int m = 250; //Integer.MAX_VALUE; //255
		byte[] mBytes = UnsignedUtil.encodeInt32(m);
		byte[] mBytesBigEndian = reverse (mBytes);
		BigInteger big = new BigInteger(mBytesBigEndian);
		assertTrue (big.intValue() == m);
	}
	
	@Test
	public void fourBytes() {
		int m = 0x030201ff;
		byte[] mBytes = UnsignedUtil.encodeInt32(m);
		byte[] mBytesBigEndian = reverse (mBytes);
		BigInteger big = new BigInteger(mBytesBigEndian);
		assertTrue (big.intValue() == m);	
		assertTrue(mBytes[0]==-1);
		assertTrue(mBytes[1]==0x01);
		assertTrue(mBytes[2]==0x02);
		assertTrue(mBytes[3]==0x03);
	}
	
	@Test
	public void twoBytes() {
		int m = 0x01ff;
		byte[] mBytes = UnsignedUtil.encodeInt(m);
		byte[] mBytesBigEndian = reverse (mBytes);
		BigInteger big = new BigInteger(mBytesBigEndian);
		assertTrue (big.intValue() == m);	
		assertTrue(mBytes[0]==-1);
		assertTrue(mBytes[1]==0x01);
	}

	private byte[] reverse(byte[] mBytes) {
		byte[] bigEndian = new byte[mBytes.length];
		for (int i = 0; i < bigEndian.length; i++) {
			bigEndian[i] = mBytes[mBytes.length-1-i];
		}
		return bigEndian;
	}

}
