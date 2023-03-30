package com.consec.iotsafe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.PINException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.PrivateKey;
import javacard.security.RandomData;
import javacard.security.SecretKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * @author Emir Rizvanovic
 *
 */
public class IoTSafeApplet extends Applet {
	
	/** Applet version */ 
	private static final byte appletVersion[] = 
		{(byte)0x01, (byte)0x15};
	
	/** PIN and PUK sizes as defined during activation */
	private static byte pinSize = (byte)0;
	private static byte pukSize = (byte)0;
	/** PIN and PUK initial retry counter as defined during activation */
	private static byte pinInitialRetryCounter = (byte)0;
	private static byte pukInitialRetryCounter = (byte)0;

	/** RandomData object, allocated on demand */
	static RandomData randomData = null;

	/** Working objects buffer used during object creation functions */
	public static byte workingBuffer[] = null;  
    
    /** OwnerPIN objects, allocated on demand */
    private static OwnerPIN userPin, puk;  
    
    /** Signature instances */
    private static Signature ecDsaSha224Signature = null;
    private static Signature ecDsaSha256Signature = null;
    private static Signature ecDsaSha384Signature = null;
    private static Signature ecDsaSha512Signature = null;
    private static Signature ecDsaNoneSignature   = null;
    
    /** Cipher instances */
    private static Cipher aesCBCCipher = null;
    private static Cipher aesECBCipher = null;
    private static Cipher rsaPlainCipher = null;

    
    /** Array for chaining incoming certificate objects */
    private static byte chainingIncomingCertsBuffer[] = null;
    
    /** Array for chaining incoming key objects as well as further chained input data */
    private static byte chainingIncomingDataBuffer[] = null;
   
    /** Chaining flag
     * Byte1-Byte2 -> short value(TRUE/FALSE) -> chaining is active or not
     * Byte3        -> byte value -> chaining INS byte
     * Byte4-Byte5 -> short value -> chaining offset
     */
    private static byte chainingIncomingController[] = null;  
    
    /** Array reference for chaining outgoing data */
    private static byte chainingOutgoingBuffer[] = null;
    
    /** Lentgh of chaining outgoing data */
    private static short chainingOutgoingLength = (short)0;
    
    /** Offset within array reference for chaining outgoing data */
    private static short chainingOutgoingOffset = (short)0;
    
  
    /** Keys and cert objects manager */
    private static ObjectManager objectManager = null;
    
    
    
	/**
	 * The Constructor registers the applet instance with the JCRE.
	 * The applet instance is created in the install() method.
	 * @param bArray the array containing installation parameters.
	 * @param bOffset the starting offset in bArray.
	 * @param bLength the length in bytes of the parameter data in bArray.
	 * The maximum value of length is 32.
	 */
	public IoTSafeApplet(byte[] bArray, short bOffset, byte bLength) {
		
		// check if garbage collection is supported which is mandatory for the applet
		if(true != JCSystem.isObjectDeletionSupported()) { 
			ISOException.throwIt(IoTSafeDeclarations.SW_GENERIC_ERROR);
		}
		
		// create COC chaining active array which holds chaining status
		chainingIncomingController = JCSystem.makeTransientByteArray(IoTSafeDeclarations.CHAINING_CONTROL_ARRAY_SIZE, JCSystem.CLEAR_ON_DESELECT);
		// reset chaining status
		setChainingStatus(IoTSafeDeclarations.FALSE);
		setChainingDataOffset((short)0x00);
		setChainingINSByte((byte)0x00);
		
		// create working buffer
		workingBuffer = JCSystem.makeTransientByteArray(IoTSafeDeclarations.OBJECT_WORKING_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
		
		// use working buffer as chaining buffer for incoming keys
		chainingIncomingDataBuffer = workingBuffer;
		
		// create cipher instances
		aesCBCCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		aesECBCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		rsaPlainCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
		
	    // create signature instances
		ecDsaSha224Signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_224, false);
		ecDsaSha256Signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		ecDsaSha384Signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_384, false);
		ecDsaSha512Signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);
		// proprietary jTOP algorithm CustomSignature.ALG_ECDSA_NONE
		ecDsaNoneSignature   = Signature.getInstance((byte)0x66, false); 
		
		// create random instance
		randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		
		// create keys and certificate objects manager
		objectManager = ObjectManager.getObjectManager();
		
		// The first byte of bArray is the length of the instance AID bytes.
		register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	/**
	 * The Java Card Runtime Environment will call this static method first.
	 * The installation is considered successful when the call <br>
	 * to <code>register()</code> completes without an exception.
	 * @param bArray the array containing installation parameters.
	 * @param bOffset the starting offset in bArray.
	 * @param bLength the length in bytes of the parameter data in bArray.
	 * @throws ISOException if the install method failed.
	 * @see javacard.framework.Applet#install(byte[], short, byte)
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new IoTSafeApplet(bArray, bOffset, bLength);
	}
	
	
	/* (non-Javadoc)
	 * @see javacard.framework.Applet#select()
	 */
	public boolean select() {
		
		// set chaining status flag to FALSE
		setChainingStatus(IoTSafeDeclarations.FALSE);

        return true;
    }

	/* (non-Javadoc)
	 * @see javacard.framework.Applet#process(javacard.framework.APDU)
	 */
	public void process(APDU apdu) throws ISOException {
	
		// in case of applet selection nothing to do here
		if (selectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();
		
		// first we check if this is ISO7816 GET RESPONSE APDU and handle that
		if (((buffer[ISO7816.OFFSET_INS] == IoTSafeDeclarations.IOT_GET_RESPONSE_INS) ||
			 (buffer[ISO7816.OFFSET_INS] == IoTSafeDeclarations.ISO7816_GET_RESPONSE_INS)) &&
			 (buffer[ISO7816.OFFSET_P1] == (byte)IoTSafeDeclarations.ZERO_BYTE) &&
			 (buffer[ISO7816.OFFSET_P2] == (byte)IoTSafeDeclarations.ZERO_BYTE)) {
			
			//return
			sendData(apdu, chainingOutgoingBuffer, chainingOutgoingOffset, (short)(chainingOutgoingLength - chainingOutgoingOffset));
			return;
		}
		
		// reset outgoing chaining variables after completing the handling of GTE RESPONSE APDU commands
		if(chainingOutgoingBuffer != null) {
			chainingOutgoingBuffer = null;		
		}
		if(chainingOutgoingOffset != (short)0) {
			chainingOutgoingOffset = (short)0;
		}
		if(chainingOutgoingLength != (short)0) {
			chainingOutgoingLength = (short)0;
		}
		
		// general check for supported CLA bytes
		if ((buffer[ISO7816.OFFSET_CLA] != IoTSafeDeclarations.IOT_CLA) &&
		    (buffer[ISO7816.OFFSET_CLA] != IoTSafeDeclarations.IOT_CLA_CHAIN)) {
	        
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	    }	
		
		// local flag to keep the chaining status locally and set the global status only 
		// when chaining is done in order to avoid conflicts in case of errors or other 
		// issues (pending chaining) during handling of chaining APDU data
		short chainingLocalFlag = IoTSafeDeclarations.FALSE;
		
		// handle chaining commands
	    if (buffer[ISO7816.OFFSET_CLA] == IoTSafeDeclarations.IOT_CLA_CHAIN) {
	    	      
	    	if(IoTSafeDeclarations.TRUE != getChainingStatus()) {
	    		// set local flag here to signalize start of chaining
	    		chainingLocalFlag = IoTSafeDeclarations.TRUE;
	    		// start chaining
	    		startChaining(apdu);
	    	}
	    	else {
	    		// we store the chaining status locally and force global flag
	    		// to false in order to avoid conflicts in case of errors or 
	    		// other issues (pending chaining) during handling of chaining 
	    		chainingLocalFlag = getChainingStatus();
	    		Util.setShort(chainingIncomingController, (short)0, IoTSafeDeclarations.FALSE);
	    		
	    		handleChaining(apdu);
	    	}
	    		
    		// as this is not the last chaining APDU then we just return
    		// and wait to receive and handle the next one, additionally
	    	// we set the chaining status here as processing has finished
	    	setChainingStatus(chainingLocalFlag);
    		
    		return;
		}    
	    
	    // handle last chaining command by processing it below
	    if (IoTSafeDeclarations.TRUE == getChainingStatus()) {	
	    	
	    	// we store the chaining status locally and force global flag
    		// to false in order to avoid conflicts in case of errors or 
    		// other issues (pending chaining) during handling of chaining 
    		chainingLocalFlag = getChainingStatus();
    		setChainingStatus(IoTSafeDeclarations.FALSE);
    		
	    	handleChaining(apdu);
		}
     	
		try {
	        switch (buffer[ISO7816.OFFSET_INS]) {
		        case IoTSafeDeclarations.PKI_STORE_CERTIFICATE_INS:        	
		        	storeCertificate(apdu, buffer, chainingLocalFlag);
		        	if (IoTSafeDeclarations.FALSE != chainingLocalFlag) {	
		    	    	resetChaining();
		    		}
		            break;
		        case IoTSafeDeclarations.PKI_LIST_OBJECTS_INS:        	
		            listObjects(apdu, buffer);
		            break;
		        case IoTSafeDeclarations.PKI_SET_OBJECT_INFO_DATA_INS:        	
		        	setObjectInfoData(apdu, buffer);
		            break;	  
		        case IoTSafeDeclarations.PKI_GET_OBJECT_INFO_DATA_INS:        	
		        	getObjectInfoData(apdu, buffer);
		            break;
		        case IoTSafeDeclarations.PKI_GET_PUBLIC_KEY_DATA_INS:        	
		        	getPublicKeyData(apdu, buffer);
		            break;
		        case IoTSafeDeclarations.PKI_GET_PRIVATE_KEY_DATA_INS:        	
		        	getPrivateKeyData(apdu, buffer);
		            break;
		        case IoTSafeDeclarations.PKI_GET_CERTIFICATE_DATA_INS:        	
		        	getCertificateData(apdu, buffer);
		            break;
		        case IoTSafeDeclarations.PKI_GENERATE_KEY_PAIR_INS:        	
		            generateKeyPair(apdu, buffer);
		            break;
		        case IoTSafeDeclarations.PKI_STORE_PRIVATE_KEY_INS: 
		        	storePrivateKey(apdu, buffer, chainingLocalFlag);
		        	if (IoTSafeDeclarations.FALSE != chainingLocalFlag) {	
		    	    	resetChaining();
		    		}
		            break;
		        case IoTSafeDeclarations.PKI_STORE_PUBLIC_KEY_INS:        	
		        	storePublicKey(apdu, buffer, chainingLocalFlag);
		        	if (IoTSafeDeclarations.FALSE != chainingLocalFlag) {	
		    	    	resetChaining();
		    		}
		            break;
		        case IoTSafeDeclarations.PKI_GENERATE_SECRET_KEY_INS:        	
		            generateSecretKey(apdu, buffer);
		            break;
		        case IoTSafeDeclarations.PKI_STORE_SECRET_KEY_INS:        	
		            storeSecretKey(apdu, buffer);
		            break;
		        case IoTSafeDeclarations.PKI_DELETE_OBJECT_INS:        	
		            deleteObject(apdu, buffer);
		            break;    	            
		        case IoTSafeDeclarations.PKI_SIGN_INS:        	
		        	signData(apdu, buffer, chainingLocalFlag);
		        	if (IoTSafeDeclarations.FALSE != chainingLocalFlag) {	
		    	    	resetChaining();
		    		}
		            break;
		        case IoTSafeDeclarations.PKI_DECRYPT_INS: 
		        	decryptData(apdu, buffer, chainingLocalFlag);
		        	if (IoTSafeDeclarations.FALSE != chainingLocalFlag) {	
		    	    	resetChaining();
		    		}
		            break;
		        case IoTSafeDeclarations.PKI_WRAP_UNWRAP_INS:        	
		            wrapUnwrapData(apdu, buffer);
		            break;
		        case IoTSafeDeclarations.IOT_GET_RANDOM_INS:        	
		            getRandom(apdu, buffer);
		            break;
		        case IoTSafeDeclarations.PKI_SET_SEED_INS:        	
		            setSeed(apdu, buffer);
		            break;
	        	case IoTSafeDeclarations.PKI_ACTIVATE_PIN_INS:
	        		activatePin(apdu, buffer);
	        		break;
	            case IoTSafeDeclarations.PKI_VERIFY_PIN_INS:        	
	                verifyPin(apdu, buffer);
	                break;
	            case IoTSafeDeclarations.PKI_CHANGE_PIN_INS:
	                changePin(apdu, buffer);
	                break;
	    		case IoTSafeDeclarations.PKI_GET_PIN_STATUS_INS:
	    			getPinStatus(apdu, buffer);
	    			break;
	            case IoTSafeDeclarations.PKI_CANCEL_AUTHENTICATION_INS:
	                cancelAuthentication(apdu, buffer);
	                break;
	            case IoTSafeDeclarations.PKI_GET_APPLET_VERSION_INS:        	
		            getAppletVersion(apdu, buffer);
		            break;
	            default:
	            	ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		        }
			}
			catch(Exception ex) {
				
				if(ex instanceof ISOException) {
					
					// ISO exception we just can throw as controlled within the applet itself
					throw (ISOException)ex;
				}
				else if(ex instanceof CryptoException) {
					
					// check reason code for debugging purposes
					short exReason = ((CryptoException)ex).getReason();
					
					unexpectedState(apdu);
				}
				else
				{
					// in case of any other exception we do not do further handling here
					unexpectedState(apdu);
				}
			}
        }		
	
	/**
	 * Stores (new) certificate.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void storeCertificate(APDU apdu, byte[] buffer, short chainingFlag) {
		
		short certDataLength = (short)0;
		short outDataLength  = (short)0;
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		if(IoTSafeDeclarations.FALSE != chainingFlag) {
			
			// check if PC+P2 indicated data length is matching with totally received length
			if((short)chainingIncomingCertsBuffer.length != getChainingDataOffset()) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			// store certificate
			outDataLength = objectManager.storeCertObject(chainingIncomingCertsBuffer, (short)0, (short)chainingIncomingCertsBuffer.length, 
					buffer, (short)0);		
		}
		else {
			
			certDataLength = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
			
			// check P1 and P2 value (certificate data length)
			if(certDataLength > IoTSafeDeclarations.MAX_CERTIFICATE_SIZE) {
				ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
			}
			
			// we also don't allow certificate data length = 0
			if(certDataLength <= (short)0) {
				ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
			}
			
			// now check received data length indicated within Lc byte
			short receivedDataLength = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
			
			// check if PC+P2 indicated data length is matching with Lc byte
			if(certDataLength != receivedDataLength) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			
			// check Lc value and receive data
			checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
    		
    		// check if minimum free NVM memory would still be ensured after creation of this certificate
    		short freePersMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);
    		if((short)(freePersMem - certDataLength) < IoTSafeDeclarations.MIN_FREE_NVM_MEMORY) {
    			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
    		}
    					
			// store certificate
    		outDataLength = objectManager.storeCertObject(buffer, (short)ISO7816.OFFSET_CDATA, certDataLength, 
					buffer, (short)0);
		}
		
		// send data	
		sendData(apdu, buffer, (short)0, outDataLength);
	}
	
	
	/**
	 * Generates key pair.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void generateKeyPair(APDU apdu, byte[] buffer) {
		
		short dataLength = 0;
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		byte keyType = (byte)buffer[ISO7816.OFFSET_P1];
		byte curveType = (byte)buffer[ISO7816.OFFSET_P2];
		byte keyPairAlg = KeyParams.getKeyPairAlgorithm(keyType);
		short keySize = KeyParams.getKeySize(keyType);	
		
		
		// check P1 and P2 value
		// check key type/algorithm and size in general
		if((IoTSafeDeclarations.KEY_TYPE_UNKNOWN == keyType) ||
		   (IoTSafeDeclarations.KEY_TYPE_UNKNOWN == keyPairAlg) ||
		   (IoTSafeDeclarations.KEY_SIZE_UNKNOWN == keySize)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}		
		// check type and curve combinations
		KeyParams.checkKeyAndCurveType(keyType, curveType);
		
		// generate key pair
		dataLength = objectManager.generateKeyPair(keyPairAlg, keySize, curveType,
				buffer, ISO7816.OFFSET_CDATA, (short)ISO7816.OFFSET_LC);
		
		// send data	
		sendData(apdu, buffer, ISO7816.OFFSET_CDATA, dataLength);
	}
	
	/**
	 * Stores public key key provided through APDU buffer.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void storePublicKey(APDU apdu, byte[] buffer, short chainingFlag) {
		
		short dataLength = 0;
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		// check P1 and P2 values
		byte keyType = (byte)buffer[ISO7816.OFFSET_P1];
		byte pubKeyType = KeyParams.getPublicKeyType(keyType);
		short keySize = KeyParams.getKeySize(keyType);
		byte curveType = (byte)buffer[ISO7816.OFFSET_P2];
		
		// check P1 and P2 value
		// check key type/algorithm and size in general
		if((IoTSafeDeclarations.KEY_TYPE_UNKNOWN == keyType) ||
		   (IoTSafeDeclarations.KEY_TYPE_UNKNOWN == pubKeyType) ||
		   (IoTSafeDeclarations.KEY_SIZE_UNKNOWN == keySize)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}		
		// check type and curve combinations
		KeyParams.checkKeyAndCurveType(keyType, curveType);
		
		if(IoTSafeDeclarations.FALSE != chainingFlag) {
			// store certificate
			dataLength = objectManager.storePublicKey(pubKeyType, keySize, curveType, chainingIncomingDataBuffer, (short)0);
			
			// send data	
			sendData(apdu, chainingIncomingDataBuffer, (short)0, dataLength);
		}
		else {
			
			// check Lc value and receive data
			checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
			
			// store private key
			dataLength = objectManager.storePublicKey(pubKeyType, keySize, curveType, buffer, ISO7816.OFFSET_CDATA);
			
			// send data	
			sendData(apdu, buffer, ISO7816.OFFSET_CDATA, dataLength);
		}
	}
	
	
	/**
	 * Stores private key key provided through APDU buffer.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void storePrivateKey(APDU apdu, byte[] buffer, short chainingFlag) {
		
		short dataLength = 0;
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		// check P1 and P2 values
		byte keyType = (byte)buffer[ISO7816.OFFSET_P1];
		byte privKeyType = KeyParams.getPrivateKeyType(keyType);
		short keySize = KeyParams.getKeySize(keyType);
		byte curveType = (byte)buffer[ISO7816.OFFSET_P2];
		
		// check P1 and P2 value
		// check key type/algorithm and size in general
		if((IoTSafeDeclarations.KEY_TYPE_UNKNOWN == keyType) ||
		   (IoTSafeDeclarations.KEY_TYPE_UNKNOWN == privKeyType) ||
		   (IoTSafeDeclarations.KEY_SIZE_UNKNOWN == keySize)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}		
		// check type and curve combinations
		KeyParams.checkKeyAndCurveType(keyType, curveType);
		
		if(IoTSafeDeclarations.FALSE != chainingFlag) {
			// store certificate
			dataLength = objectManager.storePrivateKey(privKeyType, keySize, curveType, chainingIncomingDataBuffer, (short)0);
			
			// send data	
			sendData(apdu, chainingIncomingDataBuffer, (short)0, dataLength);
		}
		else {
			
			// check Lc value and receive data
			checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
			
			// store private key
			dataLength = objectManager.storePrivateKey(privKeyType, keySize, curveType, buffer, ISO7816.OFFSET_CDATA);
			
			// send data	
			sendData(apdu, buffer, ISO7816.OFFSET_CDATA, dataLength);
		}	
	}
	
	
	/**
	 * Generates secret key.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void generateSecretKey(APDU apdu, byte[] buffer) {
		
		short dataLength = 0;
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		// check P1 value
		byte keyType = (byte)buffer[ISO7816.OFFSET_P1];
		byte secKeyType = KeyParams.getSecretKeyType(keyType);
		short keySize = KeyParams.getKeySize(keyType);	
		
		if((secKeyType == IoTSafeDeclarations.KEY_TYPE_UNKNOWN) ||
		   (keySize == IoTSafeDeclarations.KEY_SIZE_UNKNOWN)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check P2 value
		if((byte)buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_GENERATE_SECRET_KEY_P2) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// generate secret key
		dataLength = objectManager.generateSecretKey(IoTSafeDeclarations.KEY_TYPE_AES, secKeyType, keySize,
				buffer, ISO7816.OFFSET_CDATA);
		
		// send data	
		sendData(apdu, buffer, ISO7816.OFFSET_CDATA, dataLength);
	}	
	
	/**
	 * Stores secret key provided through APDU buffer.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void storeSecretKey(APDU apdu, byte[] buffer) {
		
		short dataLength = 0;
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		// check P1 value
		byte keyType = (byte)buffer[ISO7816.OFFSET_P1];
		byte secKeyType = KeyParams.getSecretKeyType(keyType);
		short keySize = KeyParams.getKeySize(keyType);
		
		if((secKeyType == IoTSafeDeclarations.KEY_TYPE_UNKNOWN) ||
		   (keySize == IoTSafeDeclarations.KEY_SIZE_UNKNOWN)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check P2 value
		if((byte)buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_STORE_SECRET_KEY_P2) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		
		// generate key pair
		dataLength = objectManager.storeSecretKey(IoTSafeDeclarations.KEY_TYPE_AES, secKeyType, keySize,
				buffer, ISO7816.OFFSET_CDATA, (short)ISO7816.OFFSET_LC);
		
		// send data	
		sendData(apdu, buffer, ISO7816.OFFSET_CDATA, dataLength);
	}
	
	
	/**
	 * Gets/returns certificate data.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void getCertificateData(APDU apdu, byte[] buffer) {
		
		// check P1 and P2 value
		if(((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.PKI_GET_CERTIFICATE_DATA_P1) ||
		   ((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_GET_CERTIFICATE_DATA_P2)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		
		// get certificate object instance
		CertObject certObject = objectManager.getCertificate(buffer, ISO7816.OFFSET_CDATA);
		
		// send data	
		sendData(apdu, certObject.getCertificateData(), (short)0, 
				certObject.getCertificateDataSize());
	}
	
	
	/**
	 * Gets/returns public key data.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void getPublicKeyData(APDU apdu, byte[] buffer) {

		short dataLength = (short)0;
		
		// check P1 value
		if(((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.RSA_KEY_MODULUS) &&
		   ((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.RSA_PUBLIC_KEY_EXPONENT) &&
		   ((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.EC_FP_PUBLIC_KEY)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check P2 value
		if((byte)buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_GET_PUBLIC_KEY_DATA_P2) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		
		PubKeyObject pubKey = objectManager.getPublicKey(buffer, ISO7816.OFFSET_CDATA);
		
		// get/copy data into working buffer as chaining might be needed in this case
		dataLength = pubKey.getPubKeyData((byte) buffer[ISO7816.OFFSET_P1], workingBuffer, (short)0);
				
		// send data	
		sendData(apdu, workingBuffer, (short)0, dataLength);
	}
	
	/**
	 * Gets/returns private key data.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void getPrivateKeyData(APDU apdu, byte[] buffer) {

		short dataLength = (short)0;
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		// check P1 value
		if((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.RSA_KEY_MODULUS) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check P2 value
		if((byte)buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_GET_PRIVATE_KEY_DATA_P2) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		
		PrivKeyObject privKey = objectManager.getPrivateKey(buffer, ISO7816.OFFSET_CDATA);
		
		// get/copy data into working buffer as chaining might be needed in this case
		dataLength = privKey.getPrivKeyData((byte) buffer[ISO7816.OFFSET_P1], workingBuffer, (short)0);
				
		// send data	
		sendData(apdu, workingBuffer, (short)0, dataLength);
	}
	

	
	/**
	 * Lists objects.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void listObjects(APDU apdu, byte[] buffer) {
		
		short dataLength = (short)0;
		
		// check P1 and P2 value
		if(((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.PKI_LIST_OBJECTS_P1) ||
		   ((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_LIST_OBJECTS_P2)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// list all public objects first
		
		// list certificate objects
		dataLength += objectManager.listCertificates(workingBuffer, (short)dataLength);
		// list public key objects
		dataLength += objectManager.listPublicKeys(workingBuffer, (short)dataLength);
		
		// list private/secret objects only if user is authenticated (logged in)
		// check user pin verification status
		if((userPin != null) && (false != userPin.isValidated())) {
			// check user pin verification status again
			// check user pin verification status
			if((userPin != null) && (false != userPin.isValidated())) {
				// private key objects
				dataLength += objectManager.listPrivateKeys(workingBuffer, (short)dataLength);
				// secret key objects
				dataLength += objectManager.listSecretKeys(workingBuffer, (short)dataLength);
	        }
        }
		
		// send data	
		sendData(apdu, workingBuffer, (short)0, dataLength);		
	}
	
	/**
	 * Deletes object with given object ID.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void deleteObject(APDU apdu, byte[] buffer) {
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		// check P1 and P2 value
		if(((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.PKI_DELETE_OBJECT_P1) ||
		   ((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_DELETE_OBJECT_P2)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		
		switch ((byte)buffer[ISO7816.OFFSET_CDATA]) {
			case IoTSafeDeclarations.OBJECT_TYPE_RSA_PRIV_KEY:        	
	        case IoTSafeDeclarations.OBJECT_TYPE_EC_PRIV_KEY:   
	        	objectManager.deletePrivateKeyObject(buffer, ISO7816.OFFSET_CDATA);
	        	break;
	        case IoTSafeDeclarations.OBJECT_TYPE_RSA_PUB_KEY:        	
	        case IoTSafeDeclarations.OBJECT_TYPE_EC_PUB_KEY:   
	        	objectManager.deletePublicKeyObject(buffer, ISO7816.OFFSET_CDATA);
	        	break;
	        case IoTSafeDeclarations.KEY_TYPE_AES:    
	        	objectManager.deleteSecretKeyObject(buffer, ISO7816.OFFSET_CDATA);
	        	break;
	        case IoTSafeDeclarations.CERTIFICATE_TYPE_X509:        	
	        	objectManager.deleteCertObject(buffer, ISO7816.OFFSET_CDATA);
	        	break;
	        default:
	        	ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		}
	}
	
	/**
	 * Sets object additional info data of object with given object ID.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void setObjectInfoData(APDU apdu, byte[] buffer) {
		
		short tmpOffset = (short)0;
		short tmpLength = (short)0;
		PKIObject tmpObject = null;
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		// check P1 and P2 value
		if(((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.PKI_SET_OBJECT_INFO_DATA_P1) ||
		   ((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_SET_OBJECT_INFO_DATA_P2)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		tmpLength = Util.makeShort((byte)0x00, buffer[ISO7816.OFFSET_LC]);
		tmpOffset = (short)ISO7816.OFFSET_CDATA;
		
		switch ((byte)buffer[tmpOffset]) {
			case IoTSafeDeclarations.OBJECT_TYPE_RSA_PRIV_KEY:        	
	        case IoTSafeDeclarations.OBJECT_TYPE_EC_PRIV_KEY:   
	        	tmpObject = objectManager.getPrivateKey(buffer, tmpOffset);
	        	break;
	        case IoTSafeDeclarations.OBJECT_TYPE_RSA_PUB_KEY:        	
	        case IoTSafeDeclarations.OBJECT_TYPE_EC_PUB_KEY:   
	        	tmpObject = objectManager.getPublicKey(buffer, tmpOffset);
	        	break;
	        case IoTSafeDeclarations.KEY_TYPE_AES:    
	        	tmpObject = objectManager.getSecretKey(buffer, tmpOffset);
	        	break;
	        case IoTSafeDeclarations.CERTIFICATE_TYPE_X509:        	
	        	tmpObject = objectManager.getCertificate(buffer, tmpOffset);
	        	break;
	        default:
	        	ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		}
		
		if(tmpObject == null) {
			ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		}
		
		tmpLength -= (short)IoTSafeDeclarations.OBJECT_ID_SIZE;
		tmpOffset += (short)(IoTSafeDeclarations.OBJECT_ID_SIZE);
		
		// set additional object info data
		tmpObject.setUserInfoData(buffer, tmpOffset, tmpLength);		
	}
	
	/**
	 * Returns additional object info data of object with given object ID.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void getObjectInfoData(APDU apdu, byte[] buffer) {
		
		PKIObject tmpObject = null;
		
		// check P1 and P2 value
		if(((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.PKI_GET_OBJECT_INFO_DATA_P1) ||
		   ((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_GET_OBJECT_INFO_DATA_P2)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		
		switch ((byte)buffer[ISO7816.OFFSET_CDATA]) {
			case IoTSafeDeclarations.OBJECT_TYPE_RSA_PRIV_KEY:        	
	        case IoTSafeDeclarations.OBJECT_TYPE_EC_PRIV_KEY:   
	        	tmpObject = objectManager.getPrivateKey(buffer, ISO7816.OFFSET_CDATA);
	        	break;
	        case IoTSafeDeclarations.OBJECT_TYPE_RSA_PUB_KEY:        	
	        case IoTSafeDeclarations.OBJECT_TYPE_EC_PUB_KEY:   
	        	tmpObject = objectManager.getPublicKey(buffer, ISO7816.OFFSET_CDATA);
	        	break;
	        case IoTSafeDeclarations.KEY_TYPE_AES:    
	        	tmpObject = objectManager.getSecretKey(buffer, ISO7816.OFFSET_CDATA);
	        	break;
	        case IoTSafeDeclarations.CERTIFICATE_TYPE_X509:        	
	        	tmpObject = objectManager.getCertificate(buffer, ISO7816.OFFSET_CDATA);
	        	break;
	        default:
	        	ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		}
		
		if(tmpObject == null) {
			ISOException.throwIt(IoTSafeDeclarations.SW_OBJECT_NOT_AVAILABLE);
		}
		
		sendData(apdu, tmpObject.getUserInfoData(), (short)0, tmpObject.getUserInfoDataSize());
	}
	
	/**
	 * Returns from 1 up to 256 random bytes.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void getRandom(APDU apdu, byte[] buffer) {
		
		// check P1 and P2
		// check P1 and P2 value
		if(((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.IOT_GET_RANDOM_P1) ||
		   ((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.IOT_GET_RANDOM_P1)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// read Le value
		short expectedLength = apdu.setOutgoing();
        
        // generate random bytes
        randomData.generateData(buffer, (short)0, expectedLength);
        
    	// send data	
    	sendData(apdu, buffer, (short)0, expectedLength);
	}
	
	/**
	 * Sets seed of random number generator
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void setSeed(APDU apdu, byte[] buffer) {
		
		// check P1 and P2 value
		if(((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.PKI_SET_SEED_P1) ||
		   ((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_SET_SEED_P2)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		
		short seedLen = Util.makeShort((byte)0x00, buffer[ISO7816.OFFSET_LC]);
		
		// check length
		if(seedLen == (short)0) {
			ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_LENGTH);
		}
		
		// set seed
    	randomData.setSeed(buffer, (short)ISO7816.OFFSET_CDATA, seedLen);
	}
	
	/**
	 * Calculates signature of provided input data with specified private key.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void signData(APDU apdu, byte[] buffer, short chainingFlag) {
		
		Cipher tmpCipher = null;
		Signature tmpSignature = null;
		byte[] tmpBuf    = null;
		
		short tmpOffset     = (short)0;
		short tmpDataLength = (short)0;
		short sigLength     = (short)0;
		short expSignInputBlockLength = (short)0;
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		// check P2 value		
		if((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_SIGN_P2) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check P1 value
		// signature algorithm / padding scheme
		if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.SIGNATURE_RSA_2048_PLAIN) {			
			tmpCipher = rsaPlainCipher;	
			expSignInputBlockLength = IoTSafeDeclarations.CIPHER_RSA_2048_NOPAD_BLOCK_LENGTH;
		}
		else if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.SIGNATURE_ECDSA_SHA_224) {			
			tmpSignature = ecDsaSha224Signature;	
		}
		else if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.SIGNATURE_ECDSA_SHA_256) {			
			tmpSignature = ecDsaSha256Signature;	
		}
		else if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.SIGNATURE_ECDSA_SHA_384) {			
			tmpSignature = ecDsaSha384Signature;	
		}
		else if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.SIGNATURE_ECDSA_SHA_512) {			
			tmpSignature = ecDsaSha512Signature;	
		}
		else if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.SIGNATURE_ECDSA_NONE) {			
			tmpSignature = ecDsaNoneSignature;	
		}
		else {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}	
		
		if(IoTSafeDeclarations.FALSE != chainingFlag) {
			
			tmpBuf = chainingIncomingDataBuffer;
			tmpOffset = (short)0;
			tmpDataLength = (short)(getChainingDataOffset() - IoTSafeDeclarations.OBJECT_ID_SIZE);
		}
		else {
			
			// check Lc value and receive data
			checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
			
			tmpBuf = buffer;
			tmpOffset = (short)ISO7816.OFFSET_CDATA;
			tmpDataLength = Util.makeShort((byte)0x00, (byte)buffer[ISO7816.OFFSET_LC]);
			tmpDataLength -= (short)(IoTSafeDeclarations.OBJECT_ID_SIZE);
		}
		
		// check expected signature input block length if any is set
		if(expSignInputBlockLength > (short)0) {
			if(expSignInputBlockLength != tmpDataLength) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
		}
		
		// get private key instance
		PrivateKey privKey = (objectManager.getPrivateKey(tmpBuf, tmpOffset)).getPrivKey();
		
		// sign
		tmpOffset += (short)IoTSafeDeclarations.OBJECT_ID_SIZE;
		
		// for rsa plain signature is realized as encrypt with private key over plain data
		if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.SIGNATURE_RSA_2048_PLAIN) {			
			
			// initialize signature instance
			tmpCipher.init(privKey, Cipher.MODE_ENCRYPT);
		
			sigLength = tmpCipher.doFinal(tmpBuf, tmpOffset, 
	        		tmpDataLength, workingBuffer, (short)0);
		}
		else {
			
			try {
				// initialize signature instance
				tmpSignature.init(privKey, Signature.MODE_SIGN);
			
		        sigLength = tmpSignature.sign(tmpBuf, tmpOffset, 
		        		tmpDataLength, workingBuffer, (short)0);
			}
			catch(CryptoException cex) {
				ISOException.throwIt(IoTSafeDeclarations.SW_SIGNATURE_NOT_AVAILABLE_FOR_GIVEN_KEY);
			}
		}	
        
        // send data	
		sendData(apdu, workingBuffer, (short)0, sigLength);
	}
	
	
	/**
	 * Decrypts provided input data with specified private key.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void decryptData(APDU apdu, byte[] buffer, short chainingFlag) {
		
		Cipher tmpCipher = null;
		byte[] tmpBuf    = null;
		
		short tmpOffset     = (short)0;
		short tmpDataLength = (short)0;
		short expCipherBlockLength = (short)0;
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		// check P2 value		
		if((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_DECRYPT_P2) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check P1 value
		// cipher algorithm / padding scheme
		if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.CIPHER_RSA_2048_NOPAD) {			
			tmpCipher = rsaPlainCipher;	
			expCipherBlockLength = IoTSafeDeclarations.CIPHER_RSA_2048_NOPAD_BLOCK_LENGTH;
		}
		else {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}	
		
		if(IoTSafeDeclarations.FALSE != chainingFlag) {
			
			tmpBuf = chainingIncomingDataBuffer;
			tmpOffset = (short)0;
			tmpDataLength = (short)(getChainingDataOffset() - IoTSafeDeclarations.OBJECT_ID_SIZE);
		}
		else {
			
			// check Lc value and receive data
			checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
			
			tmpBuf = buffer;
			tmpOffset = (short)ISO7816.OFFSET_CDATA;
			tmpDataLength = Util.makeShort((byte)0x00, (byte)buffer[ISO7816.OFFSET_LC]);
			tmpDataLength -= (short)(IoTSafeDeclarations.OBJECT_ID_SIZE);
		}
		
		// check expected cipher block length if any is set
		if(expCipherBlockLength > (short)0) {
			if(expCipherBlockLength != tmpDataLength) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
		}
		
		// get private key instance
		PrivateKey privKey = (objectManager.getPrivateKey(tmpBuf, tmpOffset)).getPrivKey();
		
		// initialize signature instance
		tmpCipher.init(privKey, Cipher.MODE_DECRYPT);
		
		// decrypt
		tmpOffset += (short)IoTSafeDeclarations.OBJECT_ID_SIZE;
	
        short decDataLength = tmpCipher.doFinal(tmpBuf, tmpOffset, 
        		tmpDataLength, workingBuffer, (short)0);
        
        // send data	
		sendData(apdu, workingBuffer, (short)0, decDataLength);
	}

	
	/**
	 * Wraps/unwraps data provided input data with specified secret key.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void wrapUnwrapData(APDU apdu, byte[] buffer) {
		
		Cipher tmpCipher = null;
		short tmpOffset = (short)0;
		short tmpDataLength = (short)0;
		
		// check authentication state
		checkPinAuthentication(apdu);
		
		// check P1 value = cipher algorithm / padding scheme
		if((byte)buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.CIPHER_AES_128_CBC_NOPAD) {			
			tmpCipher = aesCBCCipher;			
		}
		else if((byte)buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.CIPHER_AES_128_ECB_NOPAD) {			
			tmpCipher = aesECBCipher;			
		}
		else {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}	
		
		// receive data (check also done, but needed any more here)
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		
		// determine data length and offset
		tmpDataLength = Util.makeShort((byte)0x00, (byte)buffer[ISO7816.OFFSET_LC]);
		tmpOffset = ISO7816.OFFSET_CDATA;		
			
		if(((byte)buffer[ISO7816.OFFSET_P2] == IoTSafeDeclarations.CIPHER_MODE_WRAP_INIT) ||
		   ((byte)buffer[ISO7816.OFFSET_P2] == IoTSafeDeclarations.CIPHER_MODE_UNWRAP_INIT)) {
			
			// check length
			if(tmpDataLength != IoTSafeDeclarations.OBJECT_ID_SIZE) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			// get secret key instance
			SecretKey secKey = (objectManager.getSecretKey(buffer, tmpOffset)).getSecretKey();		
			
			// initialize cipher instance
			if((byte)buffer[ISO7816.OFFSET_P2] == IoTSafeDeclarations.CIPHER_MODE_WRAP_INIT) {
				tmpCipher.init(secKey, Cipher.MODE_ENCRYPT);	
			}
			else {
				tmpCipher.init(secKey, Cipher.MODE_DECRYPT);
			}
		}
		else if(((byte)buffer[ISO7816.OFFSET_P2] == IoTSafeDeclarations.CIPHER_MODE_UPDATE) ||
				((byte)buffer[ISO7816.OFFSET_P2] == IoTSafeDeclarations.CIPHER_MODE_FINAL)) {
			
			// check block alignment of wrap/unwrap relevant data
			if((short)(tmpDataLength % IoTSafeDeclarations.AES_BLOCK_SIZE) != (short)0) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			if((byte)buffer[ISO7816.OFFSET_P2] == IoTSafeDeclarations.CIPHER_MODE_UPDATE) {
				tmpDataLength = tmpCipher.update(buffer, tmpOffset, 
		        		tmpDataLength, workingBuffer, (short)0);	
			}
			else {
				tmpDataLength = tmpCipher.doFinal(buffer, tmpOffset, 
		        		tmpDataLength, workingBuffer, (short)0);
			}
			
			// send data	
			sendData(apdu, workingBuffer, (short)0, tmpDataLength);
			
			// clean working buffer again
			Util.arrayFillNonAtomic(workingBuffer, (short)0, tmpDataLength, IoTSafeDeclarations.ZERO_BYTE);	
		} 
		else {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}   		
	}
	
	/**
	 * Activates User PIN or PUK.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void activatePin(APDU apdu, byte[] buffer) {
		
		short tmpPinOffset = (short)0;
		short tmpInDataLen = (short)0;
		
		byte tmpPinSize = (byte)0;
		byte tmpPukSize = (byte)0;
		byte tmpPinInitialRetryCounter = (byte)0;
		byte tmpPukInitialRetryCounter = (byte)0;
		
		// check P2 value
		if((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_ACTIVATE_PIN_P2) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		tmpInDataLen = Util.makeShort((byte)0x00, buffer[ISO7816.OFFSET_LC]);
		
		// first data length check
		if((tmpInDataLen < (short)(IoTSafeDeclarations.SIZE_BYTE + IoTSafeDeclarations.SIZE_BYTE + IoTSafeDeclarations.MIN_PIN_PUK_SIZE)) ||
		   (tmpInDataLen > (short)(IoTSafeDeclarations.SIZE_BYTE + IoTSafeDeclarations.SIZE_BYTE + IoTSafeDeclarations.MAX_PIN_PUK_SIZE))) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		// set user pin
		if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_ACTIVATE_PIN_P1) {
			
			// check PUK authentication state
			checkPukAuthentication(apdu);
			
			// check if user pin is already activated
			if(userPin != null) {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_ALREADY_ACTIVATED);
			}
			
			tmpPinOffset = (short)ISO7816.OFFSET_CDATA;
			
			tmpPinSize = (byte) buffer[tmpPinOffset++];
			tmpPinInitialRetryCounter = (byte) buffer[tmpPinOffset++];
			
			// after knowing pin size check total data input length now
			if(tmpInDataLen != (short)(IoTSafeDeclarations.SIZE_BYTE + IoTSafeDeclarations.SIZE_BYTE + tmpPinSize)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			if((tmpPinSize > IoTSafeDeclarations.MAX_PIN_PUK_SIZE) || (tmpPinSize < IoTSafeDeclarations.MIN_PIN_PUK_SIZE))  {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_PUK_WRONG_SIZE);
			}
			
			try {
				// new pin instance has to be created within a transaction
				JCSystem.beginTransaction();
				
				userPin = new OwnerPIN(tmpPinInitialRetryCounter, IoTSafeDeclarations.MAX_PIN_PUK_SIZE);
				userPin.update(buffer, tmpPinOffset, tmpPinSize);
				
				pinSize = tmpPinSize;
				pinInitialRetryCounter = tmpPinInitialRetryCounter;				
				
				JCSystem.commitTransaction();
			}
			catch(PINException ex) {
				ISOException.throwIt(ISO7816.SW_UNKNOWN);
			}
		}
		// set puk
		else if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_ACTIVATE_PUK_P1) {
			// check if admin pin is already activated
			if(puk != null) {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_ALREADY_ACTIVATED);
			}
			
			tmpPinOffset = (short)ISO7816.OFFSET_CDATA;
			
			tmpPukSize = (byte) buffer[tmpPinOffset++];
			tmpPukInitialRetryCounter = (byte) buffer[tmpPinOffset++];
			
			// after knowing puk size check total data input length now
			if(tmpInDataLen != (short)(IoTSafeDeclarations.SIZE_BYTE + IoTSafeDeclarations.SIZE_BYTE + tmpPukSize)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			if((tmpPukSize > IoTSafeDeclarations.MAX_PIN_PUK_SIZE) || (tmpPukSize < IoTSafeDeclarations.MIN_PIN_PUK_SIZE))  {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_PUK_WRONG_SIZE);
			}
						
			try {
				// new pin instance has to be created within a transaction
				JCSystem.beginTransaction();
				
				puk = new OwnerPIN(tmpPukInitialRetryCounter, IoTSafeDeclarations.MAX_PIN_PUK_SIZE);
				puk.update(buffer, tmpPinOffset, tmpPukSize);
				
				pukSize = tmpPukSize;
				pukInitialRetryCounter = tmpPukInitialRetryCounter;		
				
				JCSystem.commitTransaction();
			}
			catch(PINException ex) {
				ISOException.throwIt(ISO7816.SW_UNKNOWN);
			}
		}
		else {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}		
	}
	
	/**
	 * Verifies User PIN.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void verifyPin(APDU apdu, byte[] buffer) {
		
		// check P2 value
		if((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_VERIFY_PIN_P2) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		byte pinSize = (byte)buffer[ISO7816.OFFSET_LC];
		checkLcAndReceiveData(apdu, pinSize);
        
		// verify user pin
		if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_VERIFY_PIN_P1) {
				
			// check if user pin is already activated
			if(userPin == null) {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_NOT_ACTIVATED);
			}
			
			// check remaining tries
			if (userPin.getTriesRemaining() == (byte)0x00) {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED);
			}
			
			// verify pin
	        if (true != userPin.check(buffer, ISO7816.OFFSET_CDATA, pinSize)) {
	        	short tries = userPin.getTriesRemaining();
				if (tries > 0x0f)
					tries = 0x0f;
				ISOException.throwIt((short) (IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED + tries));
	        }
	        // verify pin again
	        if (true != userPin.check(buffer, ISO7816.OFFSET_CDATA, pinSize)) {
	        	short tries = userPin.getTriesRemaining();
				if (tries > 0x0f)
					tries = 0x0f;
				ISOException.throwIt((short) (IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED + tries));
	        }
		}
		// verify puk
		else if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_VERIFY_PUK_P1) {
			// check if puk is already activated
			if(puk == null) {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_NOT_ACTIVATED);
			}
			
			// check remaining tries
			if (puk.getTriesRemaining() == (byte)0x00) {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED);
			}
			
			// verify puk
	        if (true != puk.check(buffer, ISO7816.OFFSET_CDATA, pinSize)) {
	        	short tries = puk.getTriesRemaining();
				if (tries > 0x0f)
					tries = 0x0f;
				ISOException.throwIt((short) (IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED + tries));
	        }
	        // verify pin again
	        if (true != puk.check(buffer, ISO7816.OFFSET_CDATA, pinSize)) {
	        	short tries = puk.getTriesRemaining();
				if (tries > 0x0f)
					tries = 0x0f;
				ISOException.throwIt((short) (IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED + tries));
	        }
		}
		else {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}	
	}
	
	/**
	 * Changes User PIN or PUK.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void changePin(APDU apdu, byte[] buffer) {
		
		short tmpOldPinOffset = (short)0;
		short tmpNewPinOffset = (short)0;
		byte tmpNewPinSize   = (byte)0;
		short tmpInDataLen = (short)0;
		
		// check P2 value
		if((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_CHANGE_PIN_P2) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		tmpInDataLen = Util.makeShort((byte)0x00, buffer[ISO7816.OFFSET_LC]);
		
		tmpOldPinOffset = (short)ISO7816.OFFSET_CDATA;
		tmpNewPinOffset = tmpOldPinOffset;
		
        		
		// change user pin with current user pin
		if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_CHANGE_USER_PIN_P1) {
			
			//jump over old pin
			tmpNewPinOffset += (short)pinSize;
			// get new pin size
			tmpNewPinSize = buffer[tmpNewPinOffset++];
			
			// check total received data length
			if(tmpInDataLen < (short)(pinSize + IoTSafeDeclarations.SIZE_BYTE + tmpNewPinSize)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			// check if new pin size is allowed
			if((tmpNewPinSize > IoTSafeDeclarations.MAX_PIN_PUK_SIZE) || (tmpNewPinSize < IoTSafeDeclarations.MIN_PIN_PUK_SIZE))  {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_PUK_WRONG_SIZE);
			}
			
			// check if user pin is already activated
			if(userPin == null) {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_NOT_ACTIVATED);
			}
			
			// check remaining tries
			if (userPin.getTriesRemaining() == IoTSafeDeclarations.ZERO_BYTE)
	            ISOException.throwIt(IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED);
			
			// verify pin
	        if (true != userPin.check(buffer, tmpOldPinOffset, pinSize)) {
	        	short tries = userPin.getTriesRemaining();
				if (tries > 0x0f)
					tries = 0x0f;
				ISOException.throwIt((short) (IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED + tries));
	        }
	        // verify pin again
	        if (true != userPin.check(buffer, tmpOldPinOffset, pinSize)) {
	        	short tries = userPin.getTriesRemaining();
				if (tries > 0x0f)
					tries = 0x0f;
				ISOException.throwIt((short) (IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED + tries));
	        }
	        
	        try
			{
				// set reference and increase offset within a transaction 
				JCSystem.beginTransaction();
				
				// update new pin
				userPin.update(buffer, tmpNewPinOffset, tmpNewPinSize);
				pinSize = tmpNewPinSize;

				// commit transaction if arrived here
				JCSystem.commitTransaction();
			}
			catch (Exception e)
			{
				JCSystem.abortTransaction();
				ISOException.throwIt(ISO7816.SW_UNKNOWN);
			}
		}
		// change user pin with current puk
		else if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_CHANGE_USER_PIN_WITH_PUK_P1) {
			
			//jump over current puk
			tmpNewPinOffset += (short)pukSize;
			// get new pin size
			tmpNewPinSize = buffer[tmpNewPinOffset++];			
			
			// check total received data length
			if(tmpInDataLen < (short)(pukSize + IoTSafeDeclarations.SIZE_BYTE + tmpNewPinSize)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			// check if new pin size is allowed
			if((tmpNewPinSize > IoTSafeDeclarations.MAX_PIN_PUK_SIZE) || (tmpNewPinSize < IoTSafeDeclarations.MIN_PIN_PUK_SIZE))  {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_PUK_WRONG_SIZE);
			}
			
			// check if user pin and puk are both already activated
			if((userPin == null) || (puk == null)) {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_NOT_ACTIVATED);
			}
			
			// check remaining tries
			if (puk.getTriesRemaining() == IoTSafeDeclarations.ZERO_BYTE)
	            ISOException.throwIt(IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED);
			
			// verify puk
	        if (true != puk.check(buffer, tmpOldPinOffset, pukSize)) {
	        	short tries = puk.getTriesRemaining();
				if (tries > 0x0f)
					tries = 0x0f;
				ISOException.throwIt((short) (IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED + tries));
	        }
	        // verify puk again
	        if (true != puk.check(buffer, tmpOldPinOffset, pukSize)) {
	        	short tries = puk.getTriesRemaining();
				if (tries > 0x0f)
					tries = 0x0f;
				ISOException.throwIt((short) (IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED + tries));
	        }
	        
	        try
			{
				// set reference and increase offset within a transaction 
				JCSystem.beginTransaction();
				
				// update new pin
				userPin.update(buffer, tmpNewPinOffset, tmpNewPinSize);
				pinSize = tmpNewPinSize;

				// commit transaction if arrived here
				JCSystem.commitTransaction();
			}
			catch (Exception e)
			{
				JCSystem.abortTransaction();
				ISOException.throwIt(ISO7816.SW_UNKNOWN);
			}
		}
		// change puk with current puk
		else if((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_CHANGE_PUK_P1) {
			
			//jump over current puk
			tmpNewPinOffset += (short)pukSize;
			// get new pin size
			tmpNewPinSize = buffer[tmpNewPinOffset++];
			
			// check total received data length
			if(tmpInDataLen < (short)(pukSize + IoTSafeDeclarations.SIZE_BYTE + tmpNewPinSize)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			// check if new pin size is allowed
			if((tmpNewPinSize > IoTSafeDeclarations.MAX_PIN_PUK_SIZE) || (tmpNewPinSize < IoTSafeDeclarations.MIN_PIN_PUK_SIZE))  {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_PUK_WRONG_SIZE);
			}
			
			// check if user pin and puk are both already activated
			if(puk == null) {
				ISOException.throwIt(IoTSafeDeclarations.SW_PIN_NOT_ACTIVATED);
			}
			
			// check remaining tries
			if (puk.getTriesRemaining() == IoTSafeDeclarations.ZERO_BYTE)
	            ISOException.throwIt(IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED);
			
			// verify puk
	        if (true != puk.check(buffer, tmpOldPinOffset, pukSize)) {
	        	short tries = puk.getTriesRemaining();
				if (tries > 0x0f)
					tries = 0x0f;
				ISOException.throwIt((short) (IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED + tries));
	        }
	        // verify puk again
	        if (true != puk.check(buffer, tmpOldPinOffset, pukSize)) {
	        	short tries = puk.getTriesRemaining();
				if (tries > 0x0f)
					tries = 0x0f;
				ISOException.throwIt((short) (IoTSafeDeclarations.SW_PIN_AUTHENTICATION_FAILED + tries));
	        }
	        
	        try
			{
				// set reference and increase offset within a transaction 
				JCSystem.beginTransaction();
				
				// update new puk
				puk.update(buffer, tmpNewPinOffset, tmpNewPinSize);
				pukSize = tmpNewPinSize;

				// commit transaction if arrived here
				JCSystem.commitTransaction();
			}
			catch (Exception e)
			{
				JCSystem.abortTransaction();
				ISOException.throwIt(ISO7816.SW_UNKNOWN);
			}
		}
		else {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
	}
	
	/**
	 * Get PIN Status.
	 * 
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void getPinStatus(APDU apdu, byte[] buffer) {
		
		short tmpDataLength = (short)0;

		// check P2 value
		if((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_GET_PIN_STATUS_P2) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
				
		// if status of user PIN requested
		if((byte)buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_GET_USER_PIN_STATUS_P1) {
			// if PIN not activated
			if(userPin == null) {
				// store activation state (not activated)
				buffer[0] = (byte)0;	
				buffer[1] = (byte)0;
				buffer[2] = (byte)0;
				buffer[3] = (byte)0;
			}
			else {
				// store activation state (activated)
				buffer[0] = (byte)1;
				// store initial number of remaining tries in buffer[0]
				buffer[1] = pinInitialRetryCounter;			
				// store current number of remaining tries in buffer[1]
				buffer[2] = userPin.getTriesRemaining();
				// store authentication state in buffer[1]
				buffer[3] = (byte) (userPin.isValidated() ? 1 : 0);
			}			
			
			tmpDataLength = (short)4;
		}
		
		// if status of PUK requested
		else if((byte)buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_GET_PUK_STATUS_P1) {
			// if PUK not activated
			if(puk == null) {
				// store activation state (not activated)
				buffer[0] = (byte)0;	
				buffer[1] = (byte)0;
				buffer[2] = (byte)0;
				buffer[3] = (byte)0;
			}
			else {
				// store activation state (activated)
				buffer[0] = (byte)1;
				// store initial number of remaining tries in buffer[0]
				buffer[1] = pukInitialRetryCounter;			
				// store current number of remaining tries in buffer[1]
				buffer[2] = puk.getTriesRemaining();
				// store authentication state in buffer[1]
				buffer[3] = (byte) (puk.isValidated() ? 1 : 0);
			}			
			
			tmpDataLength = (short)4;
		}
		
		// if status of User PIN and PUK is requested
		else if((byte)buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_GET_USER_PIN_AND_PUK_STATUS_P1) {
			// if PIN not activated
			if(userPin == null) {
				// store activation state (not activated)
				buffer[0] = (byte)0;	
				buffer[1] = (byte)0;
				buffer[2] = (byte)0;
				buffer[3] = (byte)0;
			}
			else {
				// store activation state (activated)
				buffer[0] = (byte)1;
				// store initial number of remaining tries in buffer[0]
				buffer[1] = pinInitialRetryCounter;			
				// store current number of remaining tries in buffer[1]
				buffer[2] = userPin.getTriesRemaining();
				// store authentication state in buffer[1]
				buffer[3] = (byte) (userPin.isValidated() ? 1 : 0);
			}
			
			// if PUK not activated
			if(puk == null) {
				// store activation state (not activated)
				buffer[4] = (byte)0;	
				buffer[5] = (byte)0;
				buffer[6] = (byte)0;
				buffer[7] = (byte)0;
			}
			else {
				// store activation state (activated)
				buffer[4] = (byte)1;
				// store initial number of remaining tries in buffer[0]
				buffer[5] = pukInitialRetryCounter;			
				// store current number of remaining tries in buffer[1]
				buffer[6] = puk.getTriesRemaining();
				// store authentication state in buffer[1]
				buffer[7] = (byte) (puk.isValidated() ? 1 : 0);
			}
			
			tmpDataLength = (short)8;
		}
		else
		{
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);			
		}
		
		// send data
		sendData(apdu, buffer, (short)0, tmpDataLength);
	}

	/**
	 * Cancels authentication status of User or Admin PIN.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void cancelAuthentication(APDU apdu, byte[] buffer) {
		
		// check P1 value
		if(((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.PKI_CANCEL_AUTHENTICATION_USER_PIN_P1) &&
		   ((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.PKI_CANCEL_AUTHENTICATION_PUK_P1) &&
		   ((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.PKI_CANCEL_AUTHENTICATION_USER_PIN_AND_PUK_P1)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check P2 value
		if((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_CANCEL_AUTHENTICATION_P2) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, IoTSafeDeclarations.PKI_CANCEL_AUTHENTICATION_LC);
		
		// de-authenticate user pin
		if(((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_CANCEL_AUTHENTICATION_USER_PIN_P1) ||
		   ((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_CANCEL_AUTHENTICATION_USER_PIN_AND_PUK_P1)) {
	        if (userPin.isValidated()) {
	            userPin.reset();
	        }
		}
		// de-authenticate puk
		if(((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_CANCEL_AUTHENTICATION_PUK_P1) ||
		   ((byte) buffer[ISO7816.OFFSET_P1] == IoTSafeDeclarations.PKI_CANCEL_AUTHENTICATION_USER_PIN_AND_PUK_P1)) {
	        if (puk.isValidated()) {
	            puk.reset();
	        }
		}
	}
	
	
	/**
	 * Returns applet version.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void getAppletVersion(APDU apdu, byte[] buffer) {
		
		// check P1 and P2 value
		if(((byte) buffer[ISO7816.OFFSET_P1] != IoTSafeDeclarations.PKI_GET_APPLET_VERSION_P1) ||
		   ((byte) buffer[ISO7816.OFFSET_P2] != IoTSafeDeclarations.PKI_GET_APPLET_VERSION_P2)) {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
				
		sendData(apdu, appletVersion, (short)0, (short)appletVersion.length);
	}
	
	/**
	 * Resets internal APDU command chaining buffer.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void resetChaining() {
		
		setChainingStatus(IoTSafeDeclarations.FALSE);
		setChainingDataOffset((short)0x00);
		setChainingINSByte((byte)0x00);
		chainingIncomingCertsBuffer = null;	
	}
	
	/**
	 * Sets chaining status.
	 * @param status short TRUE/FALSE value
	 * @throws ISOException if the method failed.
	 */
	private void setChainingStatus(short status) {
		
		Util.setShort(chainingIncomingController, (short)IoTSafeDeclarations.CHAINING_STATUS_OFFSET, status);
	}
	
	/**
	 * Returns chaining status.
	 */
	private short getChainingStatus() {
		
		return Util.getShort(chainingIncomingController, (short)IoTSafeDeclarations.CHAINING_STATUS_OFFSET);
	}
	
	/**
	 * Sets chaining data offset.
	 * @param offset new data offset to set
	 */
	private void setChainingDataOffset(short offset) {
		
		Util.setShort(chainingIncomingController, (short)IoTSafeDeclarations.CHAINING_DATAOFFSET_OFFSET, offset);
	}
	
	/**
	 * Returns current data chaining offset
	 */
	private short getChainingDataOffset() {
		
		return Util.getShort(chainingIncomingController, (short)IoTSafeDeclarations.CHAINING_DATAOFFSET_OFFSET);
	}
	
	/**
	 * Sets chaining INS byte.
	 * @param ins INS byte to set
	 */;
	private void setChainingINSByte(byte ins) {
		
		chainingIncomingController[IoTSafeDeclarations.CHAINING_INSBYTE_OFFSET] = ins;
	}
	
	/**
	 * Returns chaining INS byte.
	 */
	private byte getChainingINSByte() {
		
		return chainingIncomingController[IoTSafeDeclarations.CHAINING_INSBYTE_OFFSET];
	}
	
	
	/**
	 * Start APDU chaining mode.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void startChaining(APDU apdu) {
		
		short tmpOffset = (short)0;
		short freePersMem = (short)0;
		short tmpCertDataLength = (short)0;
		
		byte[] buffer = apdu.getBuffer();
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		
		short lcS = Util.makeShort((byte)0x00, buffer[ISO7816.OFFSET_LC]);
		
		switch (buffer[ISO7816.OFFSET_INS]) {
	        case IoTSafeDeclarations.PKI_STORE_CERTIFICATE_INS:  
	        		    		
	    		// check authentication state
	    		checkPinAuthentication(apdu);
	    		
	    		tmpCertDataLength = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
	    		
	    		// check for maximal possible certificate length
	    		if(tmpCertDataLength > IoTSafeDeclarations.MAX_CERTIFICATE_SIZE) {
	    			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
	    		}
	    		
	    		// we also don't allow certificate data length = 0
				if(tmpCertDataLength <= (short)0) {
					ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
				}
	    		
	    		// check if minimum free NVM memory would still be ensured after creation of this certificate
	    		freePersMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);
	    		if((short)(freePersMem - tmpCertDataLength) < IoTSafeDeclarations.MIN_FREE_NVM_MEMORY) {
	    			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
	    		}
	    		
	    		// force garbage collector here in case we re-allocate the chainingCertBuffer
	    		// then the old (if any) not any more referenced object will be deleted here
	    		JCSystem.requestObjectDeletion();
	    		
	    		// set chaining INS byte
	    		setChainingINSByte(buffer[ISO7816.OFFSET_INS]);
	    						
	    		// create chaining buffer
	    		chainingIncomingCertsBuffer = new byte[tmpCertDataLength];    		

	    		// copy first portion of data
	    		tmpOffset = Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, chainingIncomingCertsBuffer, (short)0, lcS);
	    			    		
	            break;
	            
	        case IoTSafeDeclarations.PKI_STORE_PRIVATE_KEY_INS:  
	        case IoTSafeDeclarations.PKI_STORE_PUBLIC_KEY_INS: 
	        case IoTSafeDeclarations.PKI_DECRYPT_INS:  
	        case IoTSafeDeclarations.PKI_SIGN_INS:
	    		
	    		// check authentication state
	    		checkPinAuthentication(apdu);
	    		
	    		// check if minimum free NVM memory would still be ensured after creation of this certificate
	    		freePersMem = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);
	    		if((short)(freePersMem - (short)chainingIncomingDataBuffer.length) < IoTSafeDeclarations.MIN_FREE_NVM_MEMORY) {
	    			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
	    		}
	    		
	    		// set chaining ins byte
	    		setChainingINSByte(buffer[ISO7816.OFFSET_INS]);  
	    		
	    		// copy first portion of data
	    		tmpOffset = Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA), 
	    				chainingIncomingDataBuffer, (short)0x00, lcS);
	    			    		
	            break;
	            
	         default:
	        	 ISOException.throwIt(IoTSafeDeclarations.SW_CHAINING_NOT_SUPPORTED);
	        	 break;
		 }
		
		// update chaining data offset
		setChainingDataOffset(tmpOffset);       
    }
	
	
	/**
	 * Handles APDU being executed in chaining mode.
	 * @param apdu APDU object instance
	 * @throws ISOException if the method failed.
	 */
	private void handleChaining(APDU apdu) {
		
		byte[] buffer = apdu.getBuffer();
		
		// check Lc value and receive data
		checkLcAndReceiveData(apdu, buffer[ISO7816.OFFSET_LC]);
		
		if(buffer[ISO7816.OFFSET_INS] != getChainingINSByte()) {
        	// should we reset chaining here?
        	ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_INS_FOR_CHAINING);
        }
		
		short lcS = Util.makeShort((byte)0x00, buffer[ISO7816.OFFSET_LC]);		
		short tmpOffset = getChainingDataOffset();
				
		switch (buffer[ISO7816.OFFSET_INS]) {
        	 case IoTSafeDeclarations.PKI_STORE_CERTIFICATE_INS:	
        		// check authentication state
 	    		checkPinAuthentication(apdu);
 	    		
 	    		// check for a possible array overflow exception
	    		if((short)(tmpOffset + lcS) > (short)chainingIncomingCertsBuffer.length) {
	    			ISOException.throwIt(IoTSafeDeclarations.SW_WRONG_LENGTH);
	    		}
 	    		
	 	    	// copy data
	    		tmpOffset = Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA), 
	    				chainingIncomingCertsBuffer, tmpOffset, lcS);
 	   		
 	    		break;
 	    		
        	case IoTSafeDeclarations.PKI_STORE_PRIVATE_KEY_INS:  
 	        case IoTSafeDeclarations.PKI_STORE_PUBLIC_KEY_INS:
 	        case IoTSafeDeclarations.PKI_DECRYPT_INS:  
	        case IoTSafeDeclarations.PKI_SIGN_INS:
        		// check authentication state
 	    		checkPinAuthentication(apdu);
 	    		 		
 	    		// check for a possible array overflow exception
 	    		if((short)(tmpOffset + lcS) > (short)chainingIncomingDataBuffer.length) {
 	    			ISOException.throwIt(IoTSafeDeclarations.SW_NOT_ENOUGH_MEMORY_AVAILABLE);
 	    		}
 	    		
 	    		// copy data
 	    		tmpOffset = Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA), 
 	    				chainingIncomingDataBuffer, tmpOffset, lcS);
 	    		
 	    		break;
 	    		
        	 default:
	        	 ISOException.throwIt(IoTSafeDeclarations.SW_CHAINING_NOT_SUPPORTED);
	        	 break;
		 }
				
		// update chaining data offset
		setChainingDataOffset(tmpOffset);
    }
	
	/**
	 * CHecks PIN authentication
	 * @throws ISOException if the authentication fails
	 */
	private void checkPinAuthentication(APDU apdu) {
		
		// initialize security counter
	    short secCount = (short)28;
		
		// check if pin instances are activated at all
		if(userPin == null) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		
		// increment security counter
	    secCount++;
	    
	    // increment security counter
	    secCount++;
	    
    	// user pin authentication required
    	if(true != userPin.isValidated())
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    	
    	// increment security counter
	    secCount++;
    	
    	// check user pin authentication again
    	if(true != userPin.isValidated())
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    	
    	// increment security counter
	    secCount++;
	    
    	// check security counter here
		if (secCount != (short)32) {
			unexpectedState(apdu);
		}	
	}
	
	
	/**
	 * Checks PUK authentication
	 * @throws ISOException if the authentication fails
	 */
	private void checkPukAuthentication(APDU apdu) {
		
		// initialize security counter
	    short secCount = (short)24;
		
		// check if pin instances are activated at all
		if(puk == null) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		
		// increment security counter
	    secCount++;
	    
	    // increment security counter
	    secCount++;
	    
    	// check puk authentication required
    	if(true != puk.isValidated())
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    	
    	// increment security counter
	    secCount++;
	    
	    // check puk authentication again
    	if(true != puk.isValidated())
        {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    	
    	// increment security counter
	    secCount++;
	    
    	// check security counter here
		if (secCount != (short)28) {
			unexpectedState(apdu);
		}	
	}
	
	/**
	 * Received data with expected size within given APDU object instance.
	 * @param apdu APDU object instance
	 * @param expLenB expected data size to receive
	 * @throws ISOException if the method failed.
	 */
	private void checkLcAndReceiveData(APDU apdu, byte expLenB) {
		
		byte[] buffer = apdu.getBuffer();
		
		// check Lc value vs given expected size
		if(buffer[ISO7816.OFFSET_LC] != expLenB) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		short expLenS = Util.makeShort((byte) 0x00, expLenB);
		
		if(expLenS > (byte)0) {
	        if (expLenS != apdu.setIncomingAndReceive())
	            ISOException.throwIt((short)ISO7816.SW_WRONG_LENGTH);
		}
	}
	
	
	/**
	 * Unexpected exception/state caught detected.
	 * @param apdu APDU object instance
	 * @throws ISOException
	 */
	private void unexpectedState(APDU apdu) {
		
		byte[] buffer = apdu.getBuffer();
		
		// as this is an unexpected exception/state we first clean up apdu buffer to avoid any return of sensitive data
		Util.arrayFillNonAtomic(buffer, (short)0, (short)buffer.length, IoTSafeDeclarations.ZERO_BYTE);
		
		// throw a special ISOException here
		ISOException.throwIt((short)IoTSafeDeclarations.SW_GENERIC_ERROR);
	}
	
	
	/**
	 * Sends data within given APDU object instance.
	 * @param apdu APDU object instance
	 * @param data data to send
	 * @param offset offset into data 
	 * @param size size of data to sent
	 * @throws ISOException if the method failed.
	 */
	private void sendData(APDU apdu, byte[] data, short offset, short size) {
		
		/*
        if (size > PKIDeclarations.MAX_APDU_RESP_DATA_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        apdu.setOutgoing();
        apdu.setOutgoingLength(size);
        apdu.sendBytesLong(data, offset, size);
        */
		
		short remainSize = (short)0;
		
		short sendLength = (size <= IoTSafeDeclarations.MAX_APDU_RESP_DATA_LENGTH) ? size : IoTSafeDeclarations.MAX_APDU_RESP_DATA_LENGTH;
		boolean isChaining = size > IoTSafeDeclarations.MAX_APDU_RESP_DATA_LENGTH;
		
		apdu.setOutgoing();
		apdu.setOutgoingLength(sendLength);	
		apdu.sendBytesLong(data, offset, sendLength);
		
		if(isChaining) {
			
			// if chaining outgoing buffer and length are not set yet, set it here
			if(chainingOutgoingBuffer == null) {
				chainingOutgoingBuffer = data;
			}
			if(chainingOutgoingLength == (short)0) {
				chainingOutgoingLength = size;
			}		
			// update offset
			chainingOutgoingOffset += sendLength;
			
			remainSize = (short)(chainingOutgoingLength - chainingOutgoingOffset);
			
			if(remainSize >= IoTSafeDeclarations.MAX_APDU_RESP_DATA_LENGTH) {
				ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
			}
			else {
				ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00 + remainSize));
			}
		}
	}

}
