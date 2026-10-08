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
import javacardx.crypto.Cipher;


/**
 * Base class for objects held by the {@link ObjectManager}. Carries the object
 * identifier and the free-form user information data associated with it.
 */
public class PKIObject {
	
	/** Object ID */
	protected byte objectID[] = null;
	
	/** User informational data */
	protected byte userInfoData[] = null;
	
	/** User informational data size */
	protected short userInfoDataSize = (short)0;
	
	/**
     * Constructor for the PKIObject class.
     *
     */
    public PKIObject() {
    	// generate object id buffer
    	objectID = new byte[IoTSafeDeclarations.OBJECT_ID_SIZE];
    	
    	// generate user info data array with maximal size   	
    	userInfoData = new byte[IoTSafeDeclarations.USER_INFO_DATA_MAX_SIZE];
    	userInfoDataSize = (short)0;   	
    }
    
    /**
	 * Returns user info data
	 * @return none
	 */
    public byte[] getUserInfoData() {
		
		return userInfoData;
    }
    
    /**
   	 * Returns size of user info data
   	 * @return none
   	 */
    public short getUserInfoDataSize() {
	
	   return userInfoDataSize;
    }
    
    /**
	 * Sets user info data
	 * @return none
	 */
    public void setUserInfoData(byte[] buffer, short offset, short size) {
    	
    	if(size > IoTSafeDeclarations.USER_INFO_DATA_MAX_SIZE) {
    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
    	}
    	
    	Util.arrayCopyNonAtomic(buffer, offset, userInfoData, (short)0, size);
    	
    	userInfoDataSize = size;
    }
    
    /**
	 * Returns object ID
	 * @return none
	 */
    public byte[] getObjectID() {
		
		return objectID;
    }
    
    /**
	 * Generates object ID
	 * @return none
	 */
    protected void generateObjectID(byte[] inBuf, short inOffset, short inLength, byte objectType) {
    	
    	short tmpLength = (short)0;
    	
    	// first hash provided input data   
    	(ObjectManager.sha256).reset();
        tmpLength = (ObjectManager.sha256).doFinal(inBuf, inOffset, inLength, inBuf, inOffset);
    	
    	// then encrypt with card/applet unique DES3 obejct ID key
        ObjectManager.desCBCCipher.init(ObjectManager.desObjectIDKey, Cipher.MODE_ENCRYPT);
        ObjectManager.desCBCCipher.update(inBuf, inOffset, tmpLength, inBuf, inOffset);
    	
    	objectID[0] = objectType;
    	Util.arrayCopyNonAtomic(inBuf, inOffset, objectID, (short)IoTSafeDeclarations.OBJECT_TYPE_IDENTIFIER_SIZE, (short)(IoTSafeDeclarations.OBJECT_ID_SIZE - IoTSafeDeclarations.OBJECT_TYPE_IDENTIFIER_SIZE));  
    	
    	// clear provided temporary input buffer as it might contain sensitive data
    	Util.arrayFillNonAtomic(inBuf, inOffset, inLength, IoTSafeDeclarations.ZERO_BYTE);
    }
    
}
