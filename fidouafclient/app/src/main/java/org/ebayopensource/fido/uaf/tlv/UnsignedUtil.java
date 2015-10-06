/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ebayopensource.fido.uaf.tlv;

import java.io.IOException;

public class UnsignedUtil {
	
	public static int read_UAFV1_UINT16(ByteInputStream bytes) throws IOException {
		int a = bytes.readUnsignedByte();
		int b = bytes.readUnsignedByte();
		return a + b * 256;
	}
	
	public static byte[] encodeInt(int id) {
			
			byte[] bytes = new byte[2];
			bytes[0] = (byte)(id&0x00ff);
			bytes[1] = (byte)((id&0xff00)>>8);
			return bytes;
	}
}
