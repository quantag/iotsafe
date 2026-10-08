/*
 * Copyright 2023-2026 Quantag IT Solutions GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.consec.iotsafe;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Helpers for reading and writing ASN.1 DER style tag-length-value fields.
 */
public class PKIUtil {
	
	/**
	 * Parses and returns tag
	 * @return none
	 */
	static byte getTag(byte[] tlvBuffer, short offset)
	{
		return tlvBuffer[offset];
	}
	
	/**
	 * Parses and returns length
	 * @return none
	 */
	static short getLength(byte[] tlvBuffer, short offset)
	{
		short length = 0;
		
		// definite length long form
		if((tlvBuffer[(short)(offset + 1)] & IoTSafeDeclarations.ASN1_LENGTH_LONGFORM_INDICATOR) == IoTSafeDeclarations.ASN1_LENGTH_LONGFORM_INDICATOR) {
			
			// starting length octet if the first one after first length byte
			short num = (short)(tlvBuffer[(short)(offset + 1)] & IoTSafeDeclarations.ASN1_LENGTH_LONGFORM_NUMBER_OF_OCTETS);
			
			if(num > (short)2) {
				ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
			}
			
			if(num == (short)1) {
				
				// one length byte needed; mask to avoid sign extension, as a
				// byte is signed in Java and a length octet of 0x80 to 0xFF
				// would otherwise be read as a negative value
				length = (short)(tlvBuffer[(short)(offset + 2)] & 0x00FF);
			}
			else if(num == (short)2) {
				// two length bytes needed
				length = Util.makeShort(tlvBuffer[(short)(offset + 2)], tlvBuffer[(short)(offset + 3)]);
			}
		}
		// definite length short form
		else
		{
			length = (short)(tlvBuffer[(short)(offset + 1)] & IoTSafeDeclarations.ASN1_LENGTH_LONGFORM_NUMBER_OF_OCTETS);
		}
		
		return length;
	}
	
	/**
	 * Parses and returns number of length bytes
	 * @return none
	 */
	static short getNumberOfLengthBytes(byte[] tlvBuffer, short offset)
	{	
		// definite length long form
		if((tlvBuffer[(short)(offset + 1)] & IoTSafeDeclarations.ASN1_LENGTH_LONGFORM_INDICATOR) == IoTSafeDeclarations.ASN1_LENGTH_LONGFORM_INDICATOR) {
			short num = (short)(tlvBuffer[(short)(offset + 1)] & IoTSafeDeclarations.ASN1_LENGTH_LONGFORM_NUMBER_OF_OCTETS);
			
			return (short)(num + 1);
		}
		// definite length short form
		else
		{
			return (short)1;
		}
	}
	
	/**
	 * Parses and returns data offset
	 * @return none
	 */
	static short getDataOffset(byte[] tlvBuffer, short offset)
	{
		return (short)(1 + getNumberOfLengthBytes(tlvBuffer, offset));
	}
	
	/**
	 * Encode length according to ASN.1 DER encoding rules,
	 * write it to the buffer and return length of used bytes.
	 * @return number of bytes used for encoding
	 */
	static short encodeLength(short lengthToEncode, byte[] buffer, short offset)
	{
		short longFormIndicatorS = Util.makeShort((byte)0x00, IoTSafeDeclarations.ASN1_LENGTH_LONGFORM_INDICATOR);
		
		if (lengthToEncode < longFormIndicatorS) {
			// definite length short form
			buffer[offset] = (byte)((byte)lengthToEncode & IoTSafeDeclarations.ASN1_LENGTH_LONGFORM_NUMBER_OF_OCTETS);
				
			return (short)IoTSafeDeclarations.SIZE_BYTE;
		}
		else {
			// definite length long form
			
			if(lengthToEncode > 0x100) {
				// two length bytes needed
				buffer[offset] = (byte)(IoTSafeDeclarations.ASN1_LENGTH_LONGFORM_INDICATOR | 
						IoTSafeDeclarations.SIZE_SHORT);
				Util.setShort(buffer, (short)(offset + 1), lengthToEncode);
				
				return (short)(IoTSafeDeclarations.SIZE_BYTE + IoTSafeDeclarations.SIZE_SHORT);
			}
			else {
				// one length byte needed
				buffer[offset] = (byte)(IoTSafeDeclarations.ASN1_LENGTH_LONGFORM_INDICATOR | 
						IoTSafeDeclarations.SIZE_BYTE);
				buffer[(short)(offset + 1)] = (byte)lengthToEncode;
				
				return (short)(IoTSafeDeclarations.SIZE_BYTE + IoTSafeDeclarations.SIZE_BYTE);
			}
		}	
	}
		
}

