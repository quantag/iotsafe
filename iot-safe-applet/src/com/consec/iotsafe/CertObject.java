package com.consec.iotsafe;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;


/**
 * @author ER
 *
 */
public class CertObject extends PKIObject {
	
	private byte certificate[] = null;
	
	
	/**
	 * Default constructor
	 */
	public CertObject()
	{
		;
	}
	
	
	/**
	 * Populates certificate data
	 *
	 */
    public void populateCertData(byte[] buffer, short offset, short size, byte objectType) {
    	
    	byte[] oldBuf = null;  	
    	
    	// create certificate buffer here
		try
		{
			JCSystem.beginTransaction();
			oldBuf = certificate;
			certificate = new byte[size];
			if (oldBuf != null)
			{
				JCSystem.requestObjectDeletion();
			}
			JCSystem.commitTransaction();
		}
		catch (Exception e)
		{
			JCSystem.abortTransaction();
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}
    	
    	// copy certificate data
    	Util.arrayCopyNonAtomic(buffer, offset, certificate, (short)0, size);
    	
    	// generate object id from provided certificate data
    	generateObjectID(buffer, offset, size, objectType);  	
    }
	
	/**
	 * Returns certificate data
	 * @return length/size of specified certificate part
	 */
	public byte[] getCertificateData() {
		
		return certificate;
	}
	
	/**
	 * Returns certificate data size
	 * @return certificate data length/size
	 */
	public short getCertificateDataSize() {
		
		return (short)certificate.length;
	}

}
