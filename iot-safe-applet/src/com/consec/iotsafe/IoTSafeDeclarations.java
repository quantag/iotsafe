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

/**
 * Protocol constants for the IoT SAFE applet: CLA, INS, P1 and P2 values,
 * status words, object and key type identifiers, TLV tags, and size limits.
 */
public class IoTSafeDeclarations {
	
	
	/** General definitions */
	
	
	/** CLA value for IoT Safe applet for last or only command in the chain with/without secure channel */
	final static byte  IOT_CLA		  		   		       = (byte)0x80;
	/** CLA value for PKI applet for non-last command in the chain with/without secure channel */
	final static byte  IOT_CLA_CHAIN		  		       = (byte)0xB0;
	
	
	/** INS definitions */
	
	/** INS value for GET RESPONSE APDU */
	final static byte  IOT_GET_RESPONSE_INS       = (byte)0xA0;
	final static byte  ISO7816_GET_RESPONSE_INS   = (byte)0xC0;
	
	/** INS value for GET RANDOM APDU */
	final static byte  IOT_GET_RANDOM_INS = (byte)0x84;
	
	
	/** INS value for VERIFY PIN APDU */
	final static byte  PKI_VERIFY_PIN_INS	   	           = (byte)0x20;
	/** INS value for ACTIVATE PIN APDU */
	final static byte  PKI_ACTIVATE_PIN_INS	   	           = (byte)0x22;
	/** INS value for CHANGE PIN APDU */
	final static byte  PKI_CHANGE_PIN_INS	       		   = (byte)0x24;
	/** INS value for CANCEL AUTHENTICATION APDU */
	final static byte  PKI_CANCEL_AUTHENTICATION_INS	   = (byte)0x26;
	/** INS value for GET PIN STATUS APDU */
	final static byte  PKI_GET_PIN_STATUS_INS	   		   = (byte)0x28;
	
	/** INS value for LIST OBJECTS APDU */
	final static byte  PKI_LIST_OBJECTS_INS	       		   = (byte)0x30;
	/** INS value for DELETE OBJECT APDU */
	final static byte  PKI_DELETE_OBJECT_INS	       	   = (byte)0x32;
	/** INS value for SET OBJECT INFO DATA APDU */
	final static byte  PKI_SET_OBJECT_INFO_DATA_INS  	   = (byte)0x34;
	/** INS value for GET OBJECT INFO DATA APDU */
	final static byte  PKI_GET_OBJECT_INFO_DATA_INS  	   = (byte)0x36;
	/** INS value for GET PUBLIC KEY DATA APDU */
	final static byte  PKI_GET_PUBLIC_KEY_DATA_INS         = (byte)0x38;
	/** INS value for GET PRIVATE KEY DATA APDU */
	final static byte  PKI_GET_PRIVATE_KEY_DATA_INS        = (byte)0x3A;
	/** INS value for GET CERTIFICATE DATA APDU */
	final static byte  PKI_GET_CERTIFICATE_DATA_INS        = (byte)0x3C;
	
	/** INS value for GENERATE KEY PAIR APDU */
	final static byte  PKI_GENERATE_KEY_PAIR_INS  		   = (byte)0x40;
	/** INS value for STORE PRIVATE KEY APDU */
	final static byte  PKI_STORE_PRIVATE_KEY_INS  		   = (byte)0x42;
	/** INS value for STORE PUBLIC KEY APDU */
	final static byte  PKI_STORE_PUBLIC_KEY_INS  		   = (byte)0x44;
	/** INS value for GENERATE SECRET KEY APDU */
	final static byte  PKI_GENERATE_SECRET_KEY_INS  	   = (byte)0x46;
	/** INS value for STORE SECRET KEY APDU */
	final static byte  PKI_STORE_SECRET_KEY_INS  	       = (byte)0x48;
	/** INS value for STORE CERTIFICATE APDU */
	final static byte  PKI_STORE_CERTIFICATE_INS	   	   = (byte)0x4A;	
	
	
	/** INS value for SIGN APDU */
	final static byte  PKI_SIGN_INS	   					   = (byte)0x50;
	/** INS value for DECRYPT APDU */
	final static byte  PKI_DECRYPT_INS	   				   = (byte)0x52;
	/** INS value for WRAP/UNWRAP APDU */
	final static byte  PKI_WRAP_UNWRAP_INS	   			   = (byte)0x54;
	
	/** INS value for SET SEED APDU */
	/* INS 0x58 was SET SEED. It allowed any caller, without authentication, to
	 * mix chosen bytes into the generator that produces AES keys and object
	 * identifiers, and it has been removed. The applet now answers 0x58 with
	 * SW_INS_NOT_SUPPORTED. Do not reuse this INS value for anything else:
	 * a host built against an older applet would silently invoke the new
	 * command. */
	
	/** INS value for GET APPLET VERSION APDU */
	final static byte  PKI_GET_APPLET_VERSION_INS  		   = (byte)0x70;
	
	
	/** P1/P2/LC definitions */	
	
	final static byte IOT_GET_RANDOM_P1 = (byte)0x00;
	final static byte IOT_GET_RANDOM_P2 = (byte)0x00;
	
	/** P1 value for STORE CERTIFICATE APDU */
	final static byte  PKI_STORE_CERTIFICATE_P1  = (byte)0x00;
	/** P2 value for STORE CERTIFICATE APDU */
	final static byte  PKI_STORE_CERTIFICATE_P2  = (byte)0x00;	
	
	/** P2 value for STORE KEY APDU */
	final static byte  PKI_STORE_KEY_P2  = (byte)0x00;
	/** P1 value for STORE PUBLIC KEY APDU */
	final static byte  PKI_STORE_PUBLIC_KEY_P1  = (byte)0x00;
	/** P1 value for STORE PRIVATE KEY APDU */
	final static byte  PKI_STORE_PRIVATE_KEY_P1  = (byte)0x01;
	
	/** P1 value for SET OBJECT INFO DATA APDU */
	final static byte  PKI_SET_OBJECT_INFO_DATA_P1  = (byte)0x00;
	/** P2 value for SET OBJECT INFO DATA APDU */
	final static byte  PKI_SET_OBJECT_INFO_DATA_P2  = (byte)0x00;
	
	/** P1 value for GET OBJECT INFO DATA APDU */
	final static byte  PKI_GET_OBJECT_INFO_DATA_P1  = (byte)0x00;
	/** P2 value for GET OBJECT INFO DATA APDU */
	final static byte  PKI_GET_OBJECT_INFO_DATA_P2  = (byte)0x00;
	
	/** P1 value for GET CERTIFICATE DATA APDU */
	final static byte  PKI_GET_CERTIFICATE_DATA_P1  = (byte)0x00;
	/** P2 value for GET CERTIFICATE DATA APDU */
	final static byte  PKI_GET_CERTIFICATE_DATA_P2  = (byte)0x00;
	
	/** P2 value for GET PUBLIC KEY APDU */
	final static byte  PKI_GET_PUBLIC_KEY_DATA_P2  = (byte)0x00;
	
	/** P2 value for GET PRIVATE KEY APDU */
	final static byte  PKI_GET_PRIVATE_KEY_DATA_P2  = (byte)0x00;

	/** P1 value for LIST OBJECTS APDU */
	final static byte  PKI_LIST_OBJECTS_P1	       		   = (byte)0x00;
	/** P2 value for LIST OBJECTS APDU */
	final static byte  PKI_LIST_OBJECTS_P2	       		   = (byte)0x00;
	
	/** P1 value for DELETE OBJECT APDU */
	final static byte  PKI_DELETE_OBJECT_P1	= (byte)0x00;
	/** P2 value for DELETE OBJECT APDU */
	final static byte  PKI_DELETE_OBJECT_P2	= (byte)0x00;
	
	/** P2 value for SIGN APDU */
	final static byte  PKI_SIGN_P2  = (byte)0x00;
	
	/** P2 value for DECRYPT APDU */
	final static byte  PKI_DECRYPT_P2  = (byte)0x00;
	

	
	/** P2 value for GENERATE SECRET KEY APDU */
	final static byte  PKI_GENERATE_SECRET_KEY_P2  = (byte)0x00;
	
	/** P2 value for STORE SECRET KEY APDU */
	final static byte  PKI_STORE_SECRET_KEY_P2  = (byte)0x00;
	
	/** P1 value for ACTIVATE PIN APDU */
	final static byte PKI_ACTIVATE_PIN_P1               = (byte)0x00;	
	/** P1 value for ACTIVATE PUK APDU */
	final static byte PKI_ACTIVATE_PUK_P1  	            = (byte)0x01;	
	/** P2 value for ACTIVATE PIN APDU */
	final static byte PKI_ACTIVATE_PIN_P2               = (byte)0x00;
	
	/** P1 value for VERIFY PIN APDU */
	final static byte PKI_VERIFY_PIN_P1     = (byte)0x00;
	/** P1 value for VERIFY PUK APDU */
	final static byte PKI_VERIFY_PUK_P1     = (byte)0x01;
	/** P2 value for VERIFY PIN APDU */
	final static byte PKI_VERIFY_PIN_P2     = (byte)0x00;
	
	/** P1 value for CHANGE USER PIN APDU */
	final static byte PKI_CHANGE_USER_PIN_P1     	    = (byte)0x00;
	/** P1 value for CHANGE PUK APDU */
	final static byte PKI_CHANGE_PUK_P1    				= (byte)0x01;
	/** P1 value for CHANGE USER PIN WITH PUK APDU */
	final static byte PKI_CHANGE_USER_PIN_WITH_PUK_P1   = (byte)0x02;
	/** P2 value for CHANGE USER PIN APDU */
	final static byte PKI_CHANGE_PIN_P2     			= (byte)0x00;
	
	/** P1 value for GET USER PIN STATUS APDU */
	final static byte PKI_GET_USER_PIN_STATUS_P1  			  = (byte)0x00;
	/** P1 value for GET PUK STATUS APDU */
	final static byte PKI_GET_PUK_STATUS_P1 	  			  = (byte)0x01;
	/** P1 value for GET PIN and PUK STATUS APDU */
	final static byte PKI_GET_USER_PIN_AND_PUK_STATUS_P1 	  = (byte)0x02;
	/** P2 value for GET PIN STATUS APDU */
	final static byte PKI_GET_PIN_STATUS_P2  	  			  = (byte)0x00;

	
	/** P1 value for CANCEL AUTHENTICATION USER PIN APDU */
	final static byte PKI_CANCEL_AUTHENTICATION_USER_PIN_P1     		= (byte)0x00;
	/** P1 value for CANCEL AUTHENTICATION ADMIN PIN APDU */
	final static byte PKI_CANCEL_AUTHENTICATION_PUK_P1    				= (byte)0x01;
	/** P1 value for CANCEL AUTHENTICATION USER PIN AND PUK APDU */
	final static byte PKI_CANCEL_AUTHENTICATION_USER_PIN_AND_PUK_P1     = (byte)0x02;
	/** P2 value for CANCEL AUTHENTICATION APDU */
	final static byte PKI_CANCEL_AUTHENTICATION_P2              		= (byte)0x00;
	/** LC value for CANCEL AUTHENTICATION APDU */
	final static byte PKI_CANCEL_AUTHENTICATION_LC              		= (byte)0x00;
	
	/** P1 value for GET APPLET VERSION APDU */
	final static byte PKI_GET_APPLET_VERSION_P1  = (byte)0x00;
	/** P2 value for GET APPLET VERSION APDU */
	final static byte PKI_GET_APPLET_VERSION_P2  = (byte)0x00;
	
	
	/** PKI applet general error SW1/SW2 return codes */
	
    /** The command does not support command chaining */
    final static short SW_CHAINING_NOT_SUPPORTED     = (short)0x6991;
    /** The INS byte of the command does not match the running command chaining */
    final static short SW_WRONG_INS_FOR_CHAINING	 = (short)0x6992;
    /** P1 or P2 not supported */
    final static short SW_P1P2_NOT_SUPPORTED         = (short)0x6A86;
    /** Wrong length */
    final static short SW_WRONG_LENGTH	             = (short)0x6700;
    /** Wrong data */
    final static short SW_WRONG_DATA         		 = (short)0x6A80;
    /** Wrong data */
    final static short SW_GENERIC_ERROR              = (short)0x6999;
    
    /** PKI applet command specific error SW1/SW2 return codes */
    /** PIN is already activated */
    final static short SW_PIN_ALREADY_ACTIVATED       = (short)0x6985;
    /** PIN authentication failed */
    final static short SW_PIN_AUTHENTICATION_FAILED	  = (short)0x63C0;
    /** Wrong PIN/PUK size*/
    final static short SW_PIN_PUK_WRONG_SIZE          = (short)0x6A80;
    /** PIN not activated */
    final static short SW_PIN_NOT_ACTIVATED           = (short)0x6985;
    /** Not enough memory available */
    final static short SW_NOT_ENOUGH_MEMORY_AVAILABLE = (short)0x6A84;
    /** Object not available */
    final static short SW_OBJECT_NOT_AVAILABLE        = (short)0x6A80;
    /** Another object with the same id existing */
    final static short SW_ANOTHER_OBJECT_WITH_SAME_ID_EXISTING    = (short)0x6A81;
    /** Data cannot be unwrapped */
    final static short SW_DATA_CANNOT_BE_UNWRAPPED                = (short)0x6A82;
    /** Data cannot be unwrapped */
    final static short SW_SIGNATURE_NOT_AVAILABLE_FOR_GIVEN_KEY   = (short)0x6A83;
    
    /** Max PIN/PUK size */
	final static byte MAX_PIN_PUK_SIZE = (byte)8;
	/** Min PIN/PUK size */
	final static byte MIN_PIN_PUK_SIZE = (byte)4;
    
    /** TRUE */
	final static short TRUE = (short)1864;	
	/** FALSE */
	final static short FALSE = (short)6418;
	
	/** ZERO BYTE */
	final static byte ZERO_BYTE = (byte)0x00;
	/** ONE BYTE */
	final static byte ONE_BYTE  = (byte)0x01;
	/** TWO BYTE */
	final static byte TWO_BYTE  = (byte)0x02;
	/** Number of bits in one byte */
	final static byte BITS_IN_BYTE = (byte)0x08;
	
	/** SIZE IN BYTES OF TYPE SHORT */
	final static short SIZE_SHORT = 0x02;
	
	/** SIZE IN BYTES OF TYPE BYTE */
	final static short SIZE_BYTE = 0x01;
	
	/** Object ID key length in bytes */
	final static short OBJECT_ID_KEY_SIZE_IN_BYTES = (short)16;
	
	/** MAX OUT DATA LENGTH 255 bytes */
	final static short MAX_APDU_RESP_DATA_LENGTH = (short)256; // 255 or 266
	
	/** MAX WRAP UNWRAP DATA INPUT 255 bytes - OBJECT_ID_SIZE down to next block size
	 * aligned value which is 240 bytes */
	final static short MAX_WRAP_UNWRAP_DATA_INPUT = (short)240;

	/** The working buffer is partitioned so that cryptographic input and output
	 * never occupy the same bytes. Java Card does not define the behaviour of a
	 * Signature or Cipher whose input range overlaps its output range, and the
	 * incoming chaining buffer is the working buffer, so an unpartitioned buffer
	 * would alias on every chained sign and decrypt operation.
	 *
	 * Layout of the OBJECT_WORKING_BUFFER_SIZE (768) byte buffer:
	 *   [0 .. 511]   incoming data, including the leading object ID
	 *   [512 .. 767] cryptographic output
	 *
	 * The output region holds a full RSA-2048 block (256 bytes), which is the
	 * largest signature or plaintext the applet produces. The input region holds
	 * an RSA-2048 block plus the 8-byte object ID with room to spare. */

	/** Bytes of the working buffer usable for incoming chained data */
	final static short CHAINING_INPUT_BUFFER_SIZE = (short)0x200;

	/** Offset in the working buffer at which cryptographic output is written */
	final static short CRYPTO_OUTPUT_OFFSET = (short)0x200;

	/** Bytes of the working buffer reserved for cryptographic output */
	final static short CRYPTO_OUTPUT_SIZE = (short)0x100;
	
	/** AES BLOCK SIZE 16 Bytes */
	final static short AES_BLOCK_SIZE = 0x10;
	
	/** Minimal remaining free NVM memory size = 10 KB = 10240 Bytes */
	final static short MIN_FREE_NVM_MEMORY = (short)10240;
	
	/** Max number of key and certificate objects (of each type) */
	final static byte MAX_NUMBER_PKI_OBJECTS = (byte)20;
	
	/** Max object size */
	final static short  MAX_CERTIFICATE_SIZE = (short)0x7FFF;
	
	/** General working buffer size */
	final static short  OBJECT_WORKING_BUFFER_SIZE = (short)0x300;
	
	/** Size of chaining control array */
	final static byte  CHAINING_CONTROL_ARRAY_SIZE = (byte)0x05;
	
	/** Chaining status offset */
	final static short  CHAINING_STATUS_OFFSET = (short)0x00;
	
	/** Chaining INS byte offset */
	final static short  CHAINING_INSBYTE_OFFSET = (short)0x02;
	
	/** Chaining data offset offset */
	final static short  CHAINING_DATAOFFSET_OFFSET = (short)0x03;
	
	/** Size of object id */
	final static short OBJECT_ID_SIZE = (short)8;
	
	/** Size of object id */
	final static short USER_INFO_DATA_MAX_SIZE = (short)240;
	
	/** Size of certificate type identifier */
	final static short OBJECT_TYPE_IDENTIFIER_SIZE = (short)0x01;
	

	/** PKI object types */
	
	/** Key type RSA */
	final static byte OBJECT_TYPE_RSA_PRIV_KEY = (byte)0x01;
	final static byte OBJECT_TYPE_RSA_PUB_KEY  = (byte)0x02;
	
	/** Key type EC */
	final static byte OBJECT_TYPE_EC_PRIV_KEY = (byte)0x03;
	final static byte OBJECT_TYPE_EC_PUB_KEY  = (byte)0x04;
	
	/** Secret key type AES */
	final static byte KEY_TYPE_AES = (byte)0x05;
	
	/** Certificate type X509 */
	final static byte CERTIFICATE_TYPE_X509 = (byte)0x06;
		
	
	/** PKI object definitions */
	
	/** Asymmetric key types */	
	final static byte KEY_TYPE_RSA_2048  = (byte)0x01;
	final static byte KEY_TYPE_EC_FP_224 = (byte)0x02;
	final static byte KEY_TYPE_EC_FP_256 = (byte)0x03;
	final static byte KEY_TYPE_EC_FP_384 = (byte)0x04;
	final static byte KEY_TYPE_EC_FP_521 = (byte)0x05;
	/** Symmetric key types */	
	final static byte KEY_TYPE_AES_128   = (byte)0x06;
	final static byte KEY_TYPE_AES_256   = (byte)0x07;
	
	final static byte KEY_TYPE_UNKNOWN   = (byte)0x00;
	final static short KEY_SIZE_UNKNOWN  = (byte)0x00;
	
	/** ECC curves */
	final static byte ECC_CURVE_secp224k1  = (byte)0x01;
	final static byte ECC_CURVE_secp224r1  = (byte)0x02;
	final static byte ECC_CURVE_secp256k1  = (byte)0x03;
	final static byte ECC_CURVE_secp256r1  = (byte)0x04;
	final static byte ECC_CURVE_secp384r1  = (byte)0x05;
	final static byte ECC_CURVE_secp521r1  = (byte)0x06;
	
	final static byte ECC_CURVE_UNKNOWN    = (byte)0x00;

	
	/** Signature algorithms */
	final static byte SIGNATURE_RSA_2048_PLAIN   = (byte)0x01;
	final static byte SIGNATURE_ECDSA_SHA_224    = (byte)0x02;
	final static byte SIGNATURE_ECDSA_SHA_256    = (byte)0x03;
	final static byte SIGNATURE_ECDSA_SHA_384    = (byte)0x04;
	final static byte SIGNATURE_ECDSA_SHA_512    = (byte)0x05;
	final static byte SIGNATURE_ECDSA_NONE       = (byte)0x06;

	/** Cipher algorithms */
	final static byte CIPHER_RSA_2048_NOPAD 			   = (byte)0x01;
	final static short CIPHER_RSA_2048_NOPAD_BLOCK_LENGTH  = (short)256;
	final static byte CIPHER_AES_128_CBC_NOPAD     		   = (byte)0x02;
	final static byte CIPHER_AES_128_ECB_NOPAD     		   = (byte)0x03;
	
	/** Cipher mode types */
	final static byte CIPHER_MODE_WRAP_INIT 	= (byte)0x01;
	final static byte CIPHER_MODE_UNWRAP_INIT 	= (byte)0x02;
	final static byte CIPHER_MODE_UPDATE     	= (byte)0x03;
	final static byte CIPHER_MODE_FINAL         = (byte)0x04;
	
	final static byte CIPHER_TYPE_UNKNOWN   = (byte)0x00;
	final static byte CIPHER_MODE_UNKNOWN   = (byte)0x00;
	
	/** Public key parameters */
	final static byte RSA_KEY_MODULUS 	        = (byte)0x01;
	final static byte RSA_PUBLIC_KEY_EXPONENT 	= (byte)0x02;
	final static byte EC_FP_PUBLIC_KEY 			= (byte)0x03;
	
	
	/** TAG definitions */
	
	/** TAG for RSA public/private key modulus */
	final static byte TAG_RSA_MODULUS 		 = (byte)0x10;
	/** TAG for RSA public exponent */
	final static byte TAG_RSA_PUB_EXPONENT 	 = (byte)0x11;
	/** TAG for RSA private exponent */
	final static byte TAG_RSA_PRIV_EXPONENT  = (byte)0x12;
	/** TAG for ECC public key (uncompressed) */
	final static byte TAG_ECC_PUB_KEY 		 = (byte)0x13;
	/** TAG for ECC private key */
	final static byte TAG_ECC_PRIV_KEY 		 = (byte)0x14;
	/** TAG for AES secret key */
	final static byte TAG_AES_SECRET_KEY 	 = (byte)0x15;

	
	/** ASN1 definitions */
	
	/** Length byte long form coding indicator */
	final static byte ASN1_LENGTH_LONGFORM_INDICATOR 		= (byte)0x80;
	
	/** Length byte long form number of octets */
	final static byte ASN1_LENGTH_LONGFORM_NUMBER_OF_OCTETS = (byte)0x7F;	
	
	/** TAG definitions */
	
	final static byte TAG_ECC_PUBLIC_KEY = (byte)0x49;
	final static byte TAG_ECC_PUBLIC_KEY_TEMPLATE = (byte)0x86;
	final static byte TAG_RSA_PUBLIC_KEY = (byte)0x48;
	final static byte TAG_RSA_PUBLIC_KEY_MOD = (byte)0x81;
	final static byte TAG_RSA_PUBLIC_KEY_PUB_EXP = (byte)0x82;
	
	final static byte TAG_PRIV_KEY_ID = (byte)0x84;
	final static byte TAG_PUB_KEY_ID = (byte)0x85;
	final static byte TAG_SEC_KEY_ID = (byte)0x86;
	final static short LEN_KEY_ID_MAX = (short)0x14;
	final static byte TAG_PRIV_KEY_LABEL = (byte)0x74;
	final static byte TAG_PUB_KEY_LABEL = (byte)0x75;
	final static byte TAG_SEC_KEY_LABEL = (byte)0x76;
	final static short LEN_KEY_LABEL_MAX = (short)0x3C;
	
	final static byte TAG_SECRET = (byte)0xD1;
	final static short LEN_SECRET_MAX = (short)0x40;
	
	/** General data definitions */
	
	final static byte SHA_256 = (byte)0x01;
	final static byte SHA_384 = (byte)0x02;
	final static byte SHA_512 = (byte)0x04;
	final static short ALGOS_HASH = (short)(0x0000 | SHA_256);
	
	final static byte RSA_PKCS1 = (byte)0x01;
	final static byte RSA_PSS = (byte)0x02;
	final static byte ECDSA = (byte)0x04;
	final static byte ALGOS_SIGN = (byte)(0x00 | RSA_PKCS1 | RSA_PSS | ECDSA);
	
}
