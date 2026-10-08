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
import javacard.security.AESKey;
import javacard.security.SecretKey;

/**
 * An AES secret key held by the applet, together with its key type and the
 * object identifier derived from the key material.
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
