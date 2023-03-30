package com.consec.iotsafe;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * @author ER
 *
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
				
				// one length byte needed
				length = (short)(tlvBuffer[(short)(offset + 2)]);
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

