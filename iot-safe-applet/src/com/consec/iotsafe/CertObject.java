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
import javacard.framework.JCSystem;
import javacard.framework.Util;


/**
 * An X.509 certificate held by the applet.
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
