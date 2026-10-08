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
import javacard.security.PublicKey;
import javacard.security.ECPublicKey;
import javacard.security.RSAPublicKey;

/**
 * A public key held by the applet, together with its key type and the object
 * identifier derived from the key material.
 */
public class PubKeyObject extends PKIObject {
		
		/** Public key instance */
		PublicKey pubKey = null;
		
		/** Public key type */
		byte keyObjectType = IoTSafeDeclarations.KEY_TYPE_UNKNOWN;
		
		
		/**
		 * Default constructor
		 */
		public PubKeyObject()
		{
			;
		}
		
		
		/**
	     * Populates public key parameters from buffer from key instance
	     *
	     */
		public void setPubKey(byte pubKeyType, PublicKey key) {
	    	
	    	// store corresponding key instance and key type
	    	pubKey = key;
	    	keyObjectType = pubKeyType;
	    	    	
	    	// generate public key object ID
	    	generatePubKeyID();
		}
		
	
		/**
		 * Returns public key data
		 * @return none
		 */
		public short getPubKeyData(byte paramType, byte[] buffer, short offset) {
			
			switch (paramType) {
				case IoTSafeDeclarations.RSA_KEY_MODULUS:        
					if(keyObjectType != IoTSafeDeclarations.OBJECT_TYPE_RSA_PUB_KEY) {
						ISOException.throwIt((short)IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
					}
					return ((RSAPublicKey)pubKey).getModulus(buffer, offset);
				case IoTSafeDeclarations.RSA_PUBLIC_KEY_EXPONENT:        
					if(keyObjectType != IoTSafeDeclarations.OBJECT_TYPE_RSA_PUB_KEY) {
						ISOException.throwIt((short)IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
					}
					return ((RSAPublicKey)pubKey).getExponent(buffer, offset);
				case IoTSafeDeclarations.EC_FP_PUBLIC_KEY:        
					if(keyObjectType != IoTSafeDeclarations.OBJECT_TYPE_EC_PUB_KEY) {
						ISOException.throwIt((short)IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
					}
					return ((ECPublicKey)pubKey).getW(buffer, offset); 	
		        default:
		        	// throw a special ISOException here as it should never happen
		    		ISOException.throwIt((short)IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		    		return (short)0;
			}			
		}

	    
	    /**
		 * Returns key instance
		 * @return none
		 */
		PublicKey getPubKey() {
			return pubKey;
		}
		
		/**
		 * Generate public key ID
		 * @return none
		 */
		private void generatePubKeyID() {
			
			short tmpLength = 0;
			
			byte[] tmpBuf = IoTSafeApplet.workingBuffer;
	    	
	    	// reset SHA256 engine
	    	(ObjectManager.sha256).reset();	    	

	    	// get public key value depending on public key type
	    	switch (keyObjectType) {
				case IoTSafeDeclarations.OBJECT_TYPE_RSA_PUB_KEY:        	
					tmpLength = ((RSAPublicKey)pubKey).getModulus(tmpBuf, (short)0);
					break;
		        case IoTSafeDeclarations.OBJECT_TYPE_EC_PUB_KEY:        	       	
		        	tmpLength = ((ECPublicKey)pubKey).getW(tmpBuf, (short)0);
					break;
		        default:
		        	// throw a special ISOException here as it should never happen
		    		ISOException.throwIt((short)IoTSafeDeclarations.SW_GENERIC_ERROR);
			}
	    	
	    	generateObjectID(tmpBuf, (short)0, tmpLength, keyObjectType);
		}
}
