package com.consec.iotsafe;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.PrivateKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;

/**
 * @author ER
 *
 */
public class PrivKeyObject extends PKIObject {

	/** Private key instance */
	private PrivateKey privKey = null;
	
	/** Private key type */
	byte keyObjectType = IoTSafeDeclarations.KEY_TYPE_UNKNOWN;

	/**
	 * Default constructor
	 */
	public PrivKeyObject()
	{
		;
	}


	/**
	 * Populates private key parameters from key instance
	 *
	 */
	public void setPrivKey(byte privKeyType, PrivateKey key) {

		// store corresponding key instance and private key type
		privKey = key;
		keyObjectType = privKeyType;
		
		// generate private key object ID
    	generatePrivKeyID();
	}
	

	/**
	 * Returns key instance
	 * @return none
	 */
	PrivateKey getPrivKey() {
		return privKey;
	}
	
	/**
	 * Returns private key data
	 * @return none
	 */
	public short getPrivKeyData(byte paramType, byte[] buffer, short offset) {
		
		switch (paramType) {
			case IoTSafeDeclarations.RSA_KEY_MODULUS:        
				if(keyObjectType != IoTSafeDeclarations.OBJECT_TYPE_RSA_PRIV_KEY) {
					ISOException.throwIt((short)IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
				}
				return ((RSAPrivateKey)privKey).getModulus(buffer, offset);
	        default:
	        	// throw a special ISOException here as it should never happen
	    		ISOException.throwIt((short)IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
	    		return (short)0;
		}			
	}
	
	/**
	 * Sets object ID
	 * @return none
	 */
    public void setObjectID(byte[] buffer, short offset, short size) {
    	
    	if(size != IoTSafeDeclarations.OBJECT_ID_SIZE) {
    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
    	}
    	
    	Util.arrayCopyNonAtomic(buffer, offset, objectID, (short)0, 
    				IoTSafeDeclarations.OBJECT_ID_SIZE);
    	
    	// overwrite object type
    	objectID[0] = (byte)keyObjectType;
    }
    
    /**
	 * Generate private key ID
	 * @return none
	 */
	private void generatePrivKeyID() {
		
		short tmpLength = 0;
		
		byte[] tmpBuf = IoTSafeApplet.workingBuffer;
    	
    	// reset SHA256 engine
    	(ObjectManager.sha256).reset();	    	

    	// get public key value depending on public key type
    	switch (keyObjectType) {
			case IoTSafeDeclarations.OBJECT_TYPE_RSA_PRIV_KEY:        	
				tmpLength = ((RSAPrivateKey)privKey).getModulus(tmpBuf, (short)0);
				break;
	        case IoTSafeDeclarations.OBJECT_TYPE_EC_PRIV_KEY:        	       	
	        	tmpLength = ((ECPrivateKey)privKey).getS(tmpBuf, (short)0);
				break;
	        default:
	        	// throw a special ISOException here as it should never happen
	    		ISOException.throwIt((short)IoTSafeDeclarations.SW_GENERIC_ERROR);
		}
    	
    	generateObjectID(tmpBuf, (short)0, tmpLength, keyObjectType);
	}
}
