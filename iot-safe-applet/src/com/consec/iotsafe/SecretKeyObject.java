package com.consec.iotsafe;

import javacard.framework.ISOException;
import javacard.security.AESKey;
import javacard.security.SecretKey;

/**
 * @author ER
 *
 */
public class SecretKeyObject extends PKIObject {
		
		/** Secret key instance */
		SecretKey secKey = null;
		
		/** Secret key type */
		byte keyObjectType = IoTSafeDeclarations.KEY_TYPE_UNKNOWN;
		
		
		/**
		 * Default constructor
		 */
		public SecretKeyObject()
		{
			;
		}
		
		
		/**
	     * Populates secret key parameters from buffer from key instance
	     *
	     */
		public void setSecretKey(byte secKeyType, SecretKey key) {
	    	
	    	// store corresponding key instance and key type
	    	secKey = key;
	    	keyObjectType = secKeyType;
	    	    	
	    	// generate secret key object ID
	    	generateSecretKeyID();
		}	
		
	    
	    /**
		 * Returns key instance
		 * @return none
		 */
		SecretKey getSecretKey() {
			return secKey;
		}
		
		/**
		 * Generate secret key ID
		 * @return none
		 */
		private void generateSecretKeyID() {
			
			short tmpLength = 0;
			
			byte[] tmpBuf = IoTSafeApplet.workingBuffer;
	    	
	    	// reset SHA256 engine
	    	(ObjectManager.sha256).reset();	    	
	    	
	    	// get secret key value depending on secret key type
	    	switch (keyObjectType) {
				case IoTSafeDeclarations.KEY_TYPE_AES:        	
					tmpLength = ((AESKey)secKey).getKey(tmpBuf, (short)0);
					break;
		        default:
		        	// throw a special ISOException here as it should never happen
		    		ISOException.throwIt((short)IoTSafeDeclarations.SW_GENERIC_ERROR);
			}
	    	
	    	generateObjectID(tmpBuf, (short)0, tmpLength, keyObjectType);
		}
}
