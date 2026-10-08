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
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.SecretKey;
import javacardx.crypto.Cipher;


/**
 * Singleton store for the applet's PKI objects. Creates, looks up, lists and
 * deletes certificates, public keys, private keys and secret keys, and derives
 * the object identifier under which each is addressed.
 */
public class ObjectManager {
	
	/** Message digest used for object id creation */
	public static MessageDigest sha256 = null;
	
	/** DES key and cipher used for object id creation */
    public static DESKey desObjectIDKey = null;
    public static Cipher desCBCCipher = null;
	
	/** One and only singleton instance of the object manager */
	private static ObjectManager objectManager = null;
	
	/**
	 * Certificates
	 * 
	 */
	private static CertObject certificates[];

	/**
	 * Public keys
	 * 
	 */
	private static PubKeyObject pubKeys[];

	/**
	 * Private keys
	 * 
	 */
	private static PrivKeyObject privKeys[];
	
	/**
	 * Secret keys
	 * 
	 */
	private static SecretKeyObject secKeys[];
	
	/**
	 * Next free certificate object offset
	 * 
	 */
	private static short certObjectOffset = 0;
	
	/**
	 * Next free priv keyobject offset
	 * 
	 */
	private static short privKeyObjectOffset = 0;
	
	/**
	 * Next free pub key object offset
	 * 
	 */
	private static short pubKeyObjectOffset = 0;
	
	/**
	 * Next free secret key object offset
	 * 
	 */
	private static short secKeyObjectOffset = 0;
	
	/**
	 * Key pair instance for key pair generation
	 * 
	 */
	private static KeyPair tmpKeyPair = null;
	
	/**
	 * Public key instance for public key creation
	 * 
	 */
	private static PublicKey tmpPubKey = null;
	
	/**
	 * Private key instance for public key creation
	 * 
	 */
	private static PrivateKey tmpPrivKey = null;
	
	/**
	 * Secret key instance for secret key storage/generation
	 * 
	 */
	private static SecretKey tmpSecKey = null;

	/**
	 * Temporary private key object reference
	 */
	private static PrivKeyObject tmpPrivKeyObject = null;
	
	/**
	 * Temporary public key object reference
	 */
	private static PubKeyObject tmpPubKeyObject = null;
	
	/**
	 * Temporary secret key object reference
	 */
	private static SecretKeyObject tmpSecretKeyObject = null;
	
	/**
	 * Temporary certificate object reference
	 */
	private static CertObject tmpCert = null;
	
	/**
     * Constructor for the ObjectManager class.
     *
     */
    private ObjectManager()
    {
    	
    	certificates = new CertObject[IoTSafeDeclarations.MAX_NUMBER_PKI_OBJECTS];	
    	pubKeys = new PubKeyObject[IoTSafeDeclarations.MAX_NUMBER_PKI_OBJECTS];
    	privKeys = new PrivKeyObject[IoTSafeDeclarations.MAX_NUMBER_PKI_OBJECTS];
    	secKeys = new SecretKeyObject[IoTSafeDeclarations.MAX_NUMBER_PKI_OBJECTS];
    	certObjectOffset = 0;
    	privKeyObjectOffset = 0;
    	pubKeyObjectOffset = 0;
    	secKeyObjectOffset = 0;
 	
    	sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    	
		desCBCCipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		desObjectIDKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, 
        		KeyBuilder.LENGTH_DES3_2KEY, false);
		// obtain random data and use as DES3 key
		IoTSafeApplet.randomData.generateData(IoTSafeApplet.workingBuffer, (short)0, 
    			IoTSafeDeclarations.OBJECT_ID_KEY_SIZE_IN_BYTES);
    	desObjectIDKey.setKey(IoTSafeApplet.workingBuffer, (short)0);
    	// clean data
    	Util.arrayFillNonAtomic(IoTSafeApplet.workingBuffer, (short)0, 
    			IoTSafeDeclarations.OBJECT_ID_KEY_SIZE_IN_BYTES, IoTSafeDeclarations.ZERO_BYTE);
    }
    
    
    /**
     * SingleObjectManager class.
     *
     */
    public static ObjectManager getObjectManager() {
    	
    	if (objectManager == null)  {
    		objectManager = new ObjectManager();
    	}
    	
    	return objectManager;
    }
    
    /**
	 * Stores/adds new certificate object
	 * @return returned data length
	 */
	public short storeCertObject(byte[] inBuffer, short inOffset, short inSize, byte[] outBuffer, short outOffset) {
		
		if(certObjectOffset >= IoTSafeDeclarations.MAX_NUMBER_PKI_OBJECTS)
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
				
		// create new certificate in a transaction and trigger GC if necessary
		try
		{		
			JCSystem.beginTransaction();
			CertObject oldObject = tmpCert;
			tmpCert = new CertObject();		
			if (oldObject != null)
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

		// populate the new object
		tmpCert.populateCertData(inBuffer, inOffset, inSize, IoTSafeDeclarations.CERTIFICATE_TYPE_X509);
		
		// check if the cert with the same id is already existing
		for (short j = 0; j < certObjectOffset; j++) {
			if(certificates[j] != null) {
				if((byte)0 == Util.arrayCompare(tmpCert.getObjectID(), (short)0, 
						certificates[j].getObjectID(), (short)0, 
						IoTSafeDeclarations.OBJECT_ID_SIZE)) {

					tmpCert = null;
					JCSystem.requestObjectDeletion();
					ISOException.throwIt(IoTSafeDeclarations.SW_ANOTHER_OBJECT_WITH_SAME_ID_EXISTING);
				}
			}
		}

		// copy cert ID to buffer for output
		Util.arrayCopyNonAtomic(tmpCert.getObjectID(), (short)0, outBuffer, outOffset, IoTSafeDeclarations.OBJECT_ID_SIZE);

		try
		{
			// set reference and increase offset within a transaction 
			JCSystem.beginTransaction();

			// everything went well, add it to the list
			certificates[certObjectOffset] = tmpCert;	
			tmpCert = null;
			
			// increase offset
			certObjectOffset++;

			// commit transaction if arrived here
			JCSystem.commitTransaction();
		}
		catch (Exception e)
		{
			JCSystem.abortTransaction();
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}

		// return output data length (cert ID of the just created object)
		return IoTSafeDeclarations.OBJECT_ID_SIZE;
	}
	
	
	/**
	 * Generates and stores new key pair
	 * @return returned data length
	 */
	public short generateKeyPair(byte keyPairAlg, short keySize, byte curveType,
			byte[] buffer, short offset, short size) {
		
    	byte pubKeyObjectType = (byte)0;
    	byte privKeyObjectType = (byte)0;
		
		if((pubKeyObjectOffset >= IoTSafeDeclarations.MAX_NUMBER_PKI_OBJECTS) ||
		   (privKeyObjectOffset >= IoTSafeDeclarations.MAX_NUMBER_PKI_OBJECTS)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}
    	
    	// create key pair instance in a transaction and trigger GC if necessary
		try
		{
			JCSystem.beginTransaction();
			KeyPair oldKeyPair = tmpKeyPair;
			// create a new key pair instance		
    		tmpKeyPair = new KeyPair(keyPairAlg, keySize);
    		
			if (oldKeyPair != null)
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
    	
    	try {  		
    		
    		// for ALG_EC_FP key pair we have to set appropriate EC curve params
    		if(keyPairAlg == KeyPair.ALG_EC_FP) {
    			
    			pubKeyObjectType = IoTSafeDeclarations.OBJECT_TYPE_EC_PUB_KEY;
    	    	privKeyObjectType = IoTSafeDeclarations.OBJECT_TYPE_EC_PRIV_KEY;
    			
		    	ECPrivateKey privKey = (ECPrivateKey)tmpKeyPair.getPrivate();
		    	ECPublicKey pubKey = (ECPublicKey)tmpKeyPair.getPublic();
		    	
		    	KeyParams.setCurveParameters(curveType, privKey);
		    	KeyParams.setCurveParameters(curveType, pubKey);
    		}
    		else {
    			pubKeyObjectType = IoTSafeDeclarations.OBJECT_TYPE_RSA_PUB_KEY;
    	    	privKeyObjectType = IoTSafeDeclarations.OBJECT_TYPE_RSA_PRIV_KEY;
    		}
	    	
	    	// generate key pair here
	    	tmpKeyPair.genKeyPair();
    	}
    	catch(CryptoException ex) {  	
    		// in case any issue happens during setting of crypto parameters
    		// or during key pair generation, so we trigger GC because of
    		// previously generated key pair instance
    		JCSystem.requestObjectDeletion();
    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
    	}
    	
    	
    	// create new pub key in a transaction and trigger GC if necessary
		try
		{		
			JCSystem.beginTransaction();
			PubKeyObject oldObject = tmpPubKeyObject;
			tmpPubKeyObject = new PubKeyObject();		
			if (oldObject != null)
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
		
		// populate the new pub key object
		tmpPubKeyObject.setPubKey(pubKeyObjectType, tmpKeyPair.getPublic());		   	
    	
    	// create new private key in a transaction and trigger GC if necessary
		try
		{		
			JCSystem.beginTransaction();
			PrivKeyObject oldObject = tmpPrivKeyObject;
			tmpPrivKeyObject = new PrivKeyObject();		
			if (oldObject != null)
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
		
		// populate the new private key object
		tmpPrivKeyObject.setPrivKey(privKeyObjectType, tmpKeyPair.getPrivate());
		
		// now we set private key id which is equal to public key id
		tmpPrivKeyObject.setObjectID(tmpPubKeyObject.getObjectID(), (short)0, IoTSafeDeclarations.OBJECT_ID_SIZE);
		
		// copy private key object id
		offset = Util.arrayCopyNonAtomic(tmpPrivKeyObject.getObjectID(), (short)0, buffer, offset, IoTSafeDeclarations.OBJECT_ID_SIZE);	
		// copy public key object id
		Util.arrayCopyNonAtomic(tmpPubKeyObject.getObjectID(), (short)0, buffer, offset, IoTSafeDeclarations.OBJECT_ID_SIZE);
		
		try
		{
			// set reference and increase offset within a transaction 
			JCSystem.beginTransaction();
			
			// add it to the list
			pubKeys[pubKeyObjectOffset] = tmpPubKeyObject;	
			tmpPubKeyObject = null;
			// increase offset
			pubKeyObjectOffset++;

			// everything went well, add it to the list
			privKeys[privKeyObjectOffset] = tmpPrivKeyObject;	
			tmpPrivKeyObject = null;			
			// increase offset
			privKeyObjectOffset++;

			// commit transaction if arrived here
			JCSystem.commitTransaction();
		}
		catch (Exception e)
		{
			JCSystem.abortTransaction();
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}
		
		// everything went well, so we set also tmp key pair reference to null
		tmpKeyPair = null;
		// and request object deletion
		JCSystem.requestObjectDeletion();		
		
		// return written data length (IDs of the just created key objects)
		return (short)(2*IoTSafeDeclarations.OBJECT_ID_SIZE);
	}
	
	
	/**
	 * Stores/creates public key from provided buffer
	 * @return returned data length
	 */
	public short storePublicKey(byte pubKeyType, short keySize, byte curveType, byte[] buffer, short offset) {
		
		byte tlvTag = (byte)0;
		short tlvDataOffset = (short)0;
		short tlvDataLength = (short)0;
		short tmpOffset = (short)0;
		
    	byte pubKeyObjectType = (byte)0;
		
		if(pubKeyObjectOffset >= IoTSafeDeclarations.MAX_NUMBER_PKI_OBJECTS) {
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}
    	
    	// create public key instance in a transaction and trigger GC if necessary
		try
		{
			JCSystem.beginTransaction();
			PublicKey oldPubKey = tmpPubKey;
    		// create a new public key instance		
			tmpPubKey = (PublicKey)KeyBuilder.buildKey(pubKeyType, keySize, false);
    		
			if (oldPubKey != null)
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
    	
    	try {  		
    		
    		// for EC_FP public key we have to set appropriate EC curve params
    		if(pubKeyType == KeyBuilder.TYPE_EC_FP_PUBLIC) {
    			
    			pubKeyObjectType = IoTSafeDeclarations.OBJECT_TYPE_EC_PUB_KEY;
		    	KeyParams.setCurveParameters(curveType, (ECPublicKey)tmpPubKey);
		    	
		    	// check and set data here
		    	tmpOffset = offset;
				tlvTag = PKIUtil.getTag(buffer, tmpOffset);
		    	if(tlvTag != IoTSafeDeclarations.TAG_ECC_PUB_KEY) {
		    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
		    	}
		    	tlvDataOffset = PKIUtil.getDataOffset(buffer, tmpOffset);
		    	tlvDataLength = PKIUtil.getLength(buffer, tmpOffset);
		    	
		    	((ECPublicKey)tmpPubKey).setW(buffer, (short)(tmpOffset + tlvDataOffset), tlvDataLength);
    		}
    		else if(pubKeyType == KeyBuilder.TYPE_RSA_PUBLIC) {
    			
    			pubKeyObjectType = IoTSafeDeclarations.OBJECT_TYPE_RSA_PUB_KEY;
    			
    			// check and set data here
    			tmpOffset = offset;
				tlvTag = PKIUtil.getTag(buffer, tmpOffset);
		    	if(tlvTag != IoTSafeDeclarations.TAG_RSA_MODULUS) {
		    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
		    	}
		    	tlvDataOffset = PKIUtil.getDataOffset(buffer, tmpOffset);
		    	tlvDataLength = PKIUtil.getLength(buffer, tmpOffset);
		    	
		    	((RSAPublicKey)tmpPubKey).setModulus(buffer, (short)(tmpOffset + tlvDataOffset), tlvDataLength);
		    	
		    	// go to next tag
		    	tmpOffset += (short)(tlvDataOffset + tlvDataLength);
		    	tlvTag = PKIUtil.getTag(buffer, tmpOffset);
		    	if(tlvTag != IoTSafeDeclarations.TAG_RSA_PUB_EXPONENT) {
		    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
		    	}
		    	tlvDataOffset = PKIUtil.getDataOffset(buffer, tmpOffset);
		    	tlvDataLength = PKIUtil.getLength(buffer, tmpOffset);
		    	
		    	((RSAPublicKey)tmpPubKey).setExponent(buffer, (short)(tmpOffset + tlvDataOffset), tlvDataLength);
		    	
    		}
    		else {
        		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
    		}
    	}
    	catch(Exception ex) {  	
    		// in case any issue happens during setting of crypto parameters
    		// so we trigger GC because of previously generated key instance
    		JCSystem.requestObjectDeletion();
    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
    	}
    	
    	
    	// create new pub key in a transaction and trigger GC if necessary
		try
		{		
			JCSystem.beginTransaction();
			PubKeyObject oldObject = tmpPubKeyObject;
			tmpPubKeyObject = new PubKeyObject();		
			if (oldObject != null)
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
		
		// populate the new pub key object
		tmpPubKeyObject.setPubKey(pubKeyObjectType, tmpPubKey);
		
		// check if the pub key with the same id is already existing
		for (short j = 0; j < pubKeyObjectOffset; j++) {
			if(pubKeys[j] != null) {
				if((byte)0 == Util.arrayCompare(tmpPubKeyObject.getObjectID(), (short)0, 
						pubKeys[j].getObjectID(), (short)0, 
						IoTSafeDeclarations.OBJECT_ID_SIZE)) {

					tmpPubKeyObject = null;
					JCSystem.requestObjectDeletion();
					ISOException.throwIt(IoTSafeDeclarations.SW_ANOTHER_OBJECT_WITH_SAME_ID_EXISTING);
				}
			}
		}
    	
		// copy public key object id
		Util.arrayCopyNonAtomic(tmpPubKeyObject.getObjectID(), (short)0, buffer, offset, IoTSafeDeclarations.OBJECT_ID_SIZE);
		
		try
		{
			// set reference and increase offset within a transaction 
			JCSystem.beginTransaction();
			
			// add it to the list
			pubKeys[pubKeyObjectOffset] = tmpPubKeyObject;	
			tmpPubKeyObject = null;
			// increase offset
			pubKeyObjectOffset++;

			// commit transaction if arrived here
			JCSystem.commitTransaction();
		}
		catch (Exception e)
		{
			JCSystem.abortTransaction();
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}
		
		// everything went well, so we set also temporary public key reference to null
		tmpPubKey = null;
		// and request object deletion
		JCSystem.requestObjectDeletion();		
		
		// return written data length (ID of the just created key object)
		return IoTSafeDeclarations.OBJECT_ID_SIZE;
	}
	
	
	/**
	 * Stores/creates private key from provided buffer
	 * @return returned data length
	 */
	public short storePrivateKey(byte privKeyType, short keySize, byte curveType, byte[] buffer, short offset) {
		
		byte tlvTag = (byte)0;
		short tlvDataOffset = (short)0;
		short tlvDataLength = (short)0;
		short tmpOffset = (short)0;
		
    	byte privKeyObjectType = (byte)0;
		
		if(privKeyObjectOffset >= IoTSafeDeclarations.MAX_NUMBER_PKI_OBJECTS) {
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}
    	
    	// create private key instance in a transaction and trigger GC if necessary
		try
		{
			JCSystem.beginTransaction();
			PrivateKey oldPrivKey = tmpPrivKey;
    		// create a new private key instance		
			tmpPrivKey = (PrivateKey)KeyBuilder.buildKey(privKeyType, keySize, false);
    		
			if (oldPrivKey != null)
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
    	
    	try {  		
    		
    		// for EC_FP private key we have to set appropriate EC curve parameters
    		if(privKeyType == KeyBuilder.TYPE_EC_FP_PRIVATE) {
    			
    			privKeyObjectType = IoTSafeDeclarations.OBJECT_TYPE_EC_PRIV_KEY;
		    	KeyParams.setCurveParameters(curveType, (ECPrivateKey)tmpPrivKey);
		    	
		    	// check and set data here
		    	tmpOffset = offset;
				tlvTag = PKIUtil.getTag(buffer, tmpOffset);
		    	if(tlvTag != IoTSafeDeclarations.TAG_ECC_PRIV_KEY) {
		    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
		    	}
		    	tlvDataOffset = PKIUtil.getDataOffset(buffer, tmpOffset);
		    	tlvDataLength = PKIUtil.getLength(buffer, tmpOffset);
		    	
		    	((ECPrivateKey)tmpPrivKey).setS(buffer, (short)(tmpOffset + tlvDataOffset), tlvDataLength);
    		}
    		else if(privKeyType == KeyBuilder.TYPE_RSA_PRIVATE) {
    			
    			privKeyObjectType = IoTSafeDeclarations.OBJECT_TYPE_RSA_PRIV_KEY;
    			
    			// check and set data here
    			tmpOffset = offset;
				tlvTag = PKIUtil.getTag(buffer, tmpOffset);
		    	if(tlvTag != IoTSafeDeclarations.TAG_RSA_MODULUS) {
		    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
		    	}
		    	tlvDataOffset = PKIUtil.getDataOffset(buffer, tmpOffset);
		    	tlvDataLength = PKIUtil.getLength(buffer, tmpOffset);
		    	
		    	((RSAPrivateKey)tmpPrivKey).setModulus(buffer, (short)(tmpOffset + tlvDataOffset), tlvDataLength);
		    	
		    	// go to next tag
		    	tmpOffset += (short)(tlvDataOffset + tlvDataLength);
		    	tlvTag = PKIUtil.getTag(buffer, tmpOffset);
		    	if(tlvTag != IoTSafeDeclarations.TAG_RSA_PRIV_EXPONENT) {
		    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
		    	}
		    	tlvDataOffset = PKIUtil.getDataOffset(buffer, tmpOffset);
		    	tlvDataLength = PKIUtil.getLength(buffer, tmpOffset);
		    	
		    	((RSAPrivateKey)tmpPrivKey).setExponent(buffer, (short)(tmpOffset + tlvDataOffset), tlvDataLength);
		    	
    		}
    		else {
        		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
    		}
    	}
    	catch(Exception ex) {  	
    		// in case any issue happens during setting of crypto parameters
    		// so we trigger GC because of previously generated key instance
    		JCSystem.requestObjectDeletion();
    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
    	}    	
    	
    	// create new private key in a transaction and trigger GC if necessary
		try
		{		
			JCSystem.beginTransaction();
			PrivKeyObject oldObject = tmpPrivKeyObject;
			tmpPrivKeyObject = new PrivKeyObject();		
			if (oldObject != null)
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
		
		// populate the new private key object
		tmpPrivKeyObject.setPrivKey(privKeyObjectType, tmpPrivKey);		
		
		// check if the private key with the same id is already existing
		for (short j = 0; j < privKeyObjectOffset; j++) {
			if(privKeys[j] != null) {
				if((byte)0 == Util.arrayCompare(tmpPrivKeyObject.getObjectID(), (short)0, 
						privKeys[j].getObjectID(), (short)0, 
						IoTSafeDeclarations.OBJECT_ID_SIZE)) {

					tmpPrivKeyObject = null;
					JCSystem.requestObjectDeletion();
					ISOException.throwIt(IoTSafeDeclarations.SW_ANOTHER_OBJECT_WITH_SAME_ID_EXISTING);
				}
			}
		}
    	
		// copy private key object id
		Util.arrayCopyNonAtomic(tmpPrivKeyObject.getObjectID(), (short)0, buffer, offset, IoTSafeDeclarations.OBJECT_ID_SIZE);
		
		try
		{
			// set reference and increase offset within a transaction 
			JCSystem.beginTransaction();
			
			// add it to the list
			privKeys[privKeyObjectOffset] = tmpPrivKeyObject;	
			tmpPrivKeyObject = null;
			// increase offset
			privKeyObjectOffset++;

			// commit transaction if arrived here
			JCSystem.commitTransaction();
		}
		catch (Exception e)
		{
			JCSystem.abortTransaction();
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}
		
		// everything went well, so we set also temporary private key reference to null
		tmpPrivKey = null;
		// and request object deletion
		JCSystem.requestObjectDeletion();		
		
		// return written data length (ID of the just created key object)
		return IoTSafeDeclarations.OBJECT_ID_SIZE;
	}
	
	/**
	 * Generates/creates new secret key
	 * @return returned data length
	 */
	public short generateSecretKey(byte keyObjectType, byte secKeyType, short keySize, byte[] buffer, short offset) {
		
		if(secKeyObjectOffset >= IoTSafeDeclarations.MAX_NUMBER_PKI_OBJECTS) {
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}
    	
    	// create new secret key instance in a transaction and trigger GC if necessary
		try
		{
			JCSystem.beginTransaction();
			SecretKey oldSecKey = tmpSecKey;
			// create a new secret key instance		
			tmpSecKey = (SecretKey)KeyBuilder.buildKey(secKeyType, keySize, false);
    		
			if (oldSecKey != null)
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
		
		try {  		
			// generate new secret key value (we need key size in number of bytes)
			IoTSafeApplet.randomData.generateData(IoTSafeApplet.workingBuffer, (short)0, (short)(keySize/IoTSafeDeclarations.BITS_IN_BYTE));
			((AESKey)tmpSecKey).setKey(IoTSafeApplet.workingBuffer, (short)0);
			// clear working buffer
	    	Util.arrayFillNonAtomic(IoTSafeApplet.workingBuffer, (short)0, (short)IoTSafeApplet.workingBuffer.length, IoTSafeDeclarations.ZERO_BYTE);
    	}
    	catch(CryptoException ex) {  	
    		// in case any issue happens during setting of new secret key
    		JCSystem.requestObjectDeletion();
    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
    	}
    	
    	// create new secret key object in a transaction and trigger GC if necessary
		try
		{		
			JCSystem.beginTransaction();
			SecretKeyObject oldObject = tmpSecretKeyObject;
			tmpSecretKeyObject = new SecretKeyObject();		
			if (oldObject != null)
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
		
		// populate the new secret key object
		tmpSecretKeyObject.setSecretKey(keyObjectType, tmpSecKey);		   	
    		
		// copy secret key object id
		Util.arrayCopyNonAtomic(tmpSecretKeyObject.getObjectID(), (short)0, buffer, offset, IoTSafeDeclarations.OBJECT_ID_SIZE);
				
		try
		{
			// set reference and increase offset within a transaction 
			JCSystem.beginTransaction();
			
			// add it to the list
			secKeys[secKeyObjectOffset] = tmpSecretKeyObject;	
			tmpSecretKeyObject = null;
			// increase offset
			secKeyObjectOffset++;

			// commit transaction if arrived here
			JCSystem.commitTransaction();
		}
		catch (Exception e)
		{
			JCSystem.abortTransaction();
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}
		
		// everything went well, so we set also tmp key pair reference to null
		tmpSecKey = null;
		// and request object deletion
		JCSystem.requestObjectDeletion();		
		
		// return written data length (IDs of the just created key objects)
		return IoTSafeDeclarations.OBJECT_ID_SIZE;
	}
	
	
	/**
	 * Stores/creates new secret key from provided buffer
	 * @return returned data length
	 */
	public short storeSecretKey(byte keyObjectType, byte secKeyType, short keySize,
			byte[] buffer, short offset, short size) {
		
		byte tlvTag = (byte)0;
		short tlvDataOffset = (short)0;
		
		if(secKeyObjectOffset >= IoTSafeDeclarations.MAX_NUMBER_PKI_OBJECTS) {
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}
    	
    	// create new secret key instance in a transaction and trigger GC if necessary
		try
		{
			JCSystem.beginTransaction();
			SecretKey oldSecKey = tmpSecKey;
			// create a new secret key instance		
			tmpSecKey = (SecretKey)KeyBuilder.buildKey(secKeyType, keySize, false);
    		
			if (oldSecKey != null)
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
		
		try {
			
			// parse secret key data
			tlvTag = PKIUtil.getTag(buffer, offset);
	    	if(tlvTag != IoTSafeDeclarations.TAG_AES_SECRET_KEY) {
	    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
	    	}
	    	tlvDataOffset = PKIUtil.getDataOffset(buffer, offset);
	    	
			// set key data
			((AESKey)tmpSecKey).setKey(buffer, (short)(offset + tlvDataOffset));
			// clear input buffer as it contains sensitive data
	    	Util.arrayFillNonAtomic(buffer, (short)offset, size, IoTSafeDeclarations.ZERO_BYTE);
    	}
    	catch(CryptoException ex) {  	
    		// in case any issue happens during setting of new secret key
    		JCSystem.requestObjectDeletion();
    		ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_DATA);
    	}
    	
    	// create new secret key object in a transaction and trigger GC if necessary
		try
		{		
			JCSystem.beginTransaction();
			SecretKeyObject oldObject = tmpSecretKeyObject;
			tmpSecretKeyObject = new SecretKeyObject();		
			if (oldObject != null)
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
		
		// populate the new secret key object
		tmpSecretKeyObject.setSecretKey(keyObjectType, tmpSecKey);		
		
		// check if the secret key with the same id is already existing
		for (short j = 0; j < secKeyObjectOffset; j++) {
			if(secKeys[j] != null) {
				if((byte)0 == Util.arrayCompare(tmpSecretKeyObject.getObjectID(), (short)0, 
						secKeys[j].getObjectID(), (short)0, 
						IoTSafeDeclarations.OBJECT_ID_SIZE)) {

					tmpSecretKeyObject = null;
					JCSystem.requestObjectDeletion();
					ISOException.throwIt(IoTSafeDeclarations.SW_ANOTHER_OBJECT_WITH_SAME_ID_EXISTING);
				}
			}
		}
    		
		// copy secret key object id
		Util.arrayCopyNonAtomic(tmpSecretKeyObject.getObjectID(), (short)0, buffer, offset, IoTSafeDeclarations.OBJECT_ID_SIZE);
				
		try
		{
			// set reference and increase offset within a transaction 
			JCSystem.beginTransaction();
			
			// add it to the list
			secKeys[secKeyObjectOffset] = tmpSecretKeyObject;	
			tmpSecretKeyObject = null;
			// increase offset
			secKeyObjectOffset++;

			// commit transaction if arrived here
			JCSystem.commitTransaction();
		}
		catch (Exception e)
		{
			JCSystem.abortTransaction();
			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
		}
		
		// everything went well, so we set also tmp key pair reference to null
		tmpSecKey = null;
		// and request object deletion
		JCSystem.requestObjectDeletion();		
		
		// return written data length (IDs of the just created key objects)
		return IoTSafeDeclarations.OBJECT_ID_SIZE;
	}
	
	
	/**
	 * Deletes given certificate object
	 * @return none
	 */
	public void deleteCertObject(byte[] buffer, short offset) {

		// delete appropriate certificate
		for (short j = 0; j < (short)certificates.length; j++) {
			if(certificates[j] != null) {
				if((byte)0 == Util.arrayCompare(buffer, offset, 
				    certificates[j].getObjectID(), (short)0, 
					IoTSafeDeclarations.OBJECT_ID_SIZE)) {
					
					// Just move the object from the end of the array to the
					// location of the deleted object and reduce the number of
					// remaining objects -- all in a transaction
					try
					{
						JCSystem.beginTransaction();
						
						certObjectOffset--;
						
						// note: the special case that object j is the last object
						// is also covered by this code, because then j == certObjectOffset.
						certificates[j] = certificates[certObjectOffset];
						certificates[certObjectOffset] = null;
						// request object deletion as the old object will be not referenced any more
						JCSystem.requestObjectDeletion();
						
						JCSystem.commitTransaction();
					}
					catch (Exception e)
					{
						JCSystem.abortTransaction();
						ISOException.throwIt(IoTSafeDeclarations.SW_GENERIC_ERROR);
					}
					
					return;
				}
			}
		}
		
		// if we are here, we did not find the certificate
		ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		return;
	}
	
	/**
	 * Deletes given secret key object
	 * @return none
	 */
	public void deleteSecretKeyObject(byte[] buffer, short offset) {

		// delete appropriate secret key object
		for (short j = 0; j < (short)secKeys.length; j++) {
			if(secKeys[j] != null) {
				if((byte)0 == Util.arrayCompare(buffer, offset, 
						secKeys[j].getObjectID(), (short)0, 
						IoTSafeDeclarations.OBJECT_ID_SIZE)) {

					// the following replaces the call of runDefragmentation:
					// Just move the object from the end of the array to the
					// location of the deleted object and reduce the number of
					// remaining objects -- all in a transaction
					try
					{
						JCSystem.beginTransaction();
						
						secKeyObjectOffset--;
						
						// note: the special case that object j is the last object
						// is also covered by this code, because then j == secKeyObjectOffset.
						secKeys[j] = secKeys[secKeyObjectOffset];
						secKeys[secKeyObjectOffset] = null;
						// request object deletion as the old object will be not referenced any more
						JCSystem.requestObjectDeletion();
						
						JCSystem.commitTransaction();
					}
					catch (Exception e)
					{
						JCSystem.abortTransaction();
						ISOException.throwIt(IoTSafeDeclarations.SW_GENERIC_ERROR);
					}
					
					return;	
				}
			}
		}
		
		// if we are here, we did not find the key
		ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		return;
	}
	
	/**
	 * Deletes given private key object
	 * @return none
	 */
	public void deletePrivateKeyObject(byte[] buffer, short offset) {

		// delete appropriate private key object
		for (short j = 0; j < (short)privKeys.length; j++) {
			if(privKeys[j] != null) {
				if((byte)0 == Util.arrayCompare(buffer, offset, 
						privKeys[j].getObjectID(), (short)0, 
						IoTSafeDeclarations.OBJECT_ID_SIZE)) {

					// the following replaces the call of runDefragmentation:
					// Just move the object from the end of the array to the
					// location of the deleted object and reduce the number of
					// remaining objects -- all in a transaction
					try
					{
						JCSystem.beginTransaction();
						
						privKeyObjectOffset--;
						
						// note: the special case that object j is the last object
						// is also covered by this code, because then j == privKeyObjectOffset.
						privKeys[j] = privKeys[privKeyObjectOffset];
						privKeys[privKeyObjectOffset] = null;
						// request object deletion as the old object will be not referenced any more
						JCSystem.requestObjectDeletion();
						
						JCSystem.commitTransaction();
					}
					catch (Exception e)
					{
						JCSystem.abortTransaction();
						ISOException.throwIt(IoTSafeDeclarations.SW_GENERIC_ERROR); 
					}
					
					return;	
				}
			}
		}
		
		// if we are here, we did not find the key
		ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		return;
	}
	
	
	/**
	 * Deletes given public key object
	 * @return none
	 */
	public void deletePublicKeyObject(byte[] buffer, short offset) {

		// delete appropriate certificate
		for (short j = 0; j < (short)pubKeys.length; j++) {
			if(pubKeys[j] != null) {
				if((byte)0 == Util.arrayCompare(buffer, offset, 
						pubKeys[j].getObjectID(), (short)0, 
					IoTSafeDeclarations.OBJECT_ID_SIZE)) {
					
					// Just move the object from the end of the array to the
					// location of the deleted object and reduce the number of
					// remaining objects -- all in a transaction
					try
					{
						JCSystem.beginTransaction();
						
						pubKeyObjectOffset--;
						
						// note: the special case that object j is the last object
						// is also covered by this code, because then j == pubKeyObjectOffset.
						pubKeys[j] = pubKeys[pubKeyObjectOffset];
						pubKeys[pubKeyObjectOffset] = null;
						// request object deletion as the old object will be not referenced any more
						JCSystem.requestObjectDeletion();
						
						JCSystem.commitTransaction();
					}
					catch (Exception e)
					{
						JCSystem.abortTransaction();
						ISOException.throwIt(IoTSafeDeclarations.SW_GENERIC_ERROR); 
					}
					
					return;
				}
			}
		}
		
		// if we are here, we did not find the key
		ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		return;
	}
	
	
	/**
	 * List certificates of given type with given restrictions
	 * @return  number of bytes written
	 */
	public short listCertificates(byte[] buffer, short offset) {
		
		// temporary offset for object ids within the buffer
		short tmpOffset = offset;
		
		// go through the list of certificates
		for (short j = (short)0; j < certObjectOffset; j++) {
			
			// copy object id
			tmpOffset = Util.arrayCopyNonAtomic(certificates[j].getObjectID(), (short)0, buffer, tmpOffset, IoTSafeDeclarations.OBJECT_ID_SIZE);
		}

		return (short)(tmpOffset - offset);
	}
	
	
	/**
	 * List private keys of given type with given restrictions
	 * @return  number of bytes written
	 */
	public short listPrivateKeys(byte[] buffer, short offset) {
		
		// temporary offset for object ids within the buffer
		short tmpOffset = offset;
		
		// go through the list of private keys
		for (short j = (short)0; j < privKeyObjectOffset; j++) {
			
			// copy object id
			tmpOffset = Util.arrayCopyNonAtomic(privKeys[j].getObjectID(), (short)0, buffer, tmpOffset, IoTSafeDeclarations.OBJECT_ID_SIZE);
		}

		return (short)(tmpOffset - offset);
	}
	
	
	 /**
	 * List public keys of given type with given restrictions
	 * @return  number of bytes written
	 */
	public short listPublicKeys(byte[] buffer, short offset) {
		
		// temporary offset for object ids within the buffer
		short tmpOffset = offset;
		
		// go through the list of public keys
		for (short j = (short)0; j < pubKeyObjectOffset; j++) {
			
			// copy object id
			tmpOffset = Util.arrayCopyNonAtomic(pubKeys[j].getObjectID(), (short)0, buffer, tmpOffset, IoTSafeDeclarations.OBJECT_ID_SIZE);
		}

		return (short)(tmpOffset - offset);
	}
	
	/**
	 * List secret keys
	 * @return number of bytes written
	 */
	public short listSecretKeys(byte[] buffer, short offset) {

		// temporary offset for object ids within the buffer
		short tmpOffset = offset;
		
		// go through the list of secret keys
		for (short j = (short)0; j < secKeyObjectOffset; j++) {
			
			// copy object id
			tmpOffset = Util.arrayCopyNonAtomic(secKeys[j].getObjectID(), (short)0, buffer, tmpOffset, IoTSafeDeclarations.OBJECT_ID_SIZE);
		}

		return (short)(tmpOffset - offset);
	}
	
	
	/**
	 * Returns certificate instance of appropriate certificate id
	 * @return  none
	 */
	public CertObject getCertificate(byte[] buffer, short offset) {

		// look for certificate
		for (short j = 0; j < certObjectOffset; j++) {
			if(certificates[j] != null) {
				if((byte)0 == Util.arrayCompare(buffer, offset, 
						certificates[j].getObjectID(), (short)0, 
					IoTSafeDeclarations.OBJECT_ID_SIZE)) {
					
					return (CertObject)certificates[j];
				}
			}
		}
		
		// if we are here, we did not find the private key
		ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		return null;
	}
	
	
	/**
	 * Returns public key instance of appropriate private/public key id
	 * @return  none
	 */
	public PubKeyObject getPublicKey(byte[] buffer, short offset) {

		// look for public key
		for (short j = 0; j < pubKeyObjectOffset; j++) {
			if(pubKeys[j] != null) {
				if((byte)0 == Util.arrayCompare(buffer, offset, 
						pubKeys[j].getObjectID(), (short)0, 
					IoTSafeDeclarations.OBJECT_ID_SIZE)) {
					
					return (PubKeyObject)pubKeys[j];
				}
			}
		}
		
		// if we are here, we did not find the private key
		ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		return null;
	}
		
		
	/**
	 * Returns private key instance of appropriate private/public key id
	 * @return  none
	 */
	public PrivKeyObject getPrivateKey(byte[] buffer, short offset) {

		// look for private key
		for (short j = 0; j < privKeyObjectOffset; j++) {
			if(privKeys[j] != null) {
				if((byte)0 == Util.arrayCompare(buffer, offset, 
						privKeys[j].getObjectID(), (short)0, 
					IoTSafeDeclarations.OBJECT_ID_SIZE)) {
					
					return (PrivKeyObject)privKeys[j];
				}
			}
		}
		
		// if we are here, we did not find the private key
		ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		return null;
	}
	
	/**
	 * Returns secret key instance of appropriate secret key id
	 * @return  none
	 */
	public SecretKeyObject getSecretKey(byte[] buffer, short offset) {

		// look for secret key
		for (short j = 0; j < secKeyObjectOffset; j++) {
			if(secKeys[j] != null) {
				if((byte)0 == Util.arrayCompare(buffer, offset, 
						secKeys[j].getObjectID(), (short)0, 
					IoTSafeDeclarations.OBJECT_ID_SIZE)) {
					
					return (SecretKeyObject)secKeys[j];
				}
			}
		}
		
		// if we are here, we did not find the secret key
		ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		return null;
	}

}
