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
import javacard.security.ECKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacardx.crypto.Cipher;

/**
 * Elliptic curve domain parameters for the supported SEC curves, and the
 * mapping from IoT SAFE key type identifiers to Java Card key algorithms,
 * key types and key sizes.
 */
public class KeyParams {
	
	/** SECP224K1 */ 
	private final static byte SECP224K1_FP[] = 
		{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* P = FP */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, (byte)0xFF, (byte)0xFF, (byte)0xE5, (byte)0x6D};	
	private final static byte SECP224K1_A[] = 
		{(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,	/* A */
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00};	
	private final static byte SECP224K1_B[] = 
		{(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,	/* B */
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x05};	 
	private final static byte SECP224K1_G[] = 
		{(byte)0x04, (byte)0xA1, (byte)0x45, (byte)0x5B, (byte)0x33, (byte)0x4D, (byte)0xF0, (byte)0x99, (byte)0xDF, (byte)0x30,    /* G */
		 (byte)0xFC, (byte)0x28, (byte)0xA1, (byte)0x69, (byte)0xA4, (byte)0x67, (byte)0xE9, (byte)0xE4, (byte)0x70, (byte)0x75, 
		 (byte)0xA9, (byte)0x0F, (byte)0x7E, (byte)0x65, (byte)0x0E, (byte)0xB6, (byte)0xB7, (byte)0xA4, (byte)0x5C, (byte)0x7E, 
		 (byte)0x08, (byte)0x9F, (byte)0xED, (byte)0x7F, (byte)0xBA, (byte)0x34, (byte)0x42, (byte)0x82, (byte)0xCA, (byte)0xFB, 
		 (byte)0xD6, (byte)0xF7, (byte)0xE3, (byte)0x19, (byte)0xF7, (byte)0xC0, (byte)0xB0, (byte)0xBD, (byte)0x59, (byte)0xE2, 
		 (byte)0xCA, (byte)0x4B, (byte)0xDB, (byte)0x55, (byte)0x6D, (byte)0x61, (byte)0xA5};	
	private final static byte SECP224K1_R[] = 
		{(byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 	/* R = N */
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0xDC, (byte)0xE8, (byte)0xD2, (byte)0xEC, (byte)0x61, 
		 (byte)0x84, (byte)0xCA, (byte)0xF0, (byte)0xA9, (byte)0x71, (byte)0x76, (byte)0x9F, (byte)0xB1, (byte)0xF7};		
	private final static short SECP224K1_K = (short)0x01;
	
	/** SECP224R1 */ 
	private final static byte SECP224R1_FP[] = 
		{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* P = FP */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01};	
	private final static byte SECP224R1_A[] = 
		{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* A */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE};	
	private final static byte SECP224R1_B[] = 
		{(byte)0xB4, (byte)0x05, (byte)0x0A, (byte)0x85, (byte)0x0C, (byte)0x04, (byte)0xB3, (byte)0xAB, (byte)0xF5, (byte)0x41,	/* B */
		 (byte)0x32, (byte)0x56, (byte)0x50, (byte)0x44, (byte)0xB0, (byte)0xB7, (byte)0xD7, (byte)0xBF, (byte)0xD8, (byte)0xBA,
		 (byte)0x27, (byte)0x0B, (byte)0x39, (byte)0x43, (byte)0x23, (byte)0x55, (byte)0xFF, (byte)0xB4};	 
	private final static byte SECP224R1_G[] = 
		{(byte)0x04, (byte)0xB7, (byte)0x0E, (byte)0x0C, (byte)0xBD, (byte)0x6B, (byte)0xB4, (byte)0xBF, (byte)0x7F, (byte)0x32,    /* G */
		 (byte)0x13, (byte)0x90, (byte)0xB9, (byte)0x4A, (byte)0x03, (byte)0xC1, (byte)0xD3, (byte)0x56, (byte)0xC2, (byte)0x11, 
		 (byte)0x22, (byte)0x34, (byte)0x32, (byte)0x80, (byte)0xD6, (byte)0x11, (byte)0x5C, (byte)0x1D, (byte)0x21, (byte)0xBD, 
		 (byte)0x37, (byte)0x63, (byte)0x88, (byte)0xB5, (byte)0xF7, (byte)0x23, (byte)0xFB, (byte)0x4C, (byte)0x22, (byte)0xDF, 
		 (byte)0xE6, (byte)0xCD, (byte)0x43, (byte)0x75, (byte)0xA0, (byte)0x5A, (byte)0x07, (byte)0x47, (byte)0x64, (byte)0x44, 
		 (byte)0xD5, (byte)0x81, (byte)0x99, (byte)0x85, (byte)0x00, (byte)0x7E, (byte)0x34};		
	private final static byte SECP224R1_R[] = 
		{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* P = FP */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x16, (byte)0xA2, (byte)0xE0, (byte)0xB8, (byte)0xF0, (byte)0x3E,
		 (byte)0x13, (byte)0xDD, (byte)0x29, (byte)0x45, (byte)0x5C, (byte)0x5C, (byte)0x2A, (byte)0x3D};	
	private final static short SECP224R1_K = (short)0x01;
	
	/** SECP256K1 */ 
	private final static byte SECP256K1_FP[] = 
		{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* P = FP */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, (byte)0xFF, (byte)0xFF,
		 (byte)0xFC, (byte)0x2F};	
	private final static byte SECP256K1_A[] = 
		{(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,	/* A */
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		 (byte)0x00, (byte)0x00};	
	private final static byte SECP256K1_B[] = 
		{(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,	/* B */
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		 (byte)0x00, (byte)0x07};	 
	private final static byte SECP256K1_G[] = 
		{(byte)0x04, (byte)0x79, (byte)0xBE, (byte)0x66, (byte)0x7E, (byte)0xF9, (byte)0xDC, (byte)0xBB, (byte)0xAC, (byte)0x55,    /* G */
		 (byte)0xA0, (byte)0x62, (byte)0x95, (byte)0xCE, (byte)0x87, (byte)0x0B, (byte)0x07, (byte)0x02, (byte)0x9B, (byte)0xFC, 
		 (byte)0xDB, (byte)0x2D, (byte)0xCE, (byte)0x28, (byte)0xD9, (byte)0x59, (byte)0xF2, (byte)0x81, (byte)0x5B, (byte)0x16, 
		 (byte)0xF8, (byte)0x17, (byte)0x98, (byte)0x48, (byte)0x3A, (byte)0xDA, (byte)0x77, (byte)0x26, (byte)0xA3, (byte)0xC4, 
		 (byte)0x65, (byte)0x5D, (byte)0xA4, (byte)0xFB, (byte)0xFC, (byte)0x0E, (byte)0x11, (byte)0x08, (byte)0xA8, (byte)0xFD, 
		 (byte)0x17, (byte)0xB4, (byte)0x48, (byte)0xA6, (byte)0x85, (byte)0x54, (byte)0x19, (byte)0x9C, (byte)0x47, (byte)0xD0, 
		 (byte)0x8F, (byte)0xFB, (byte)0x10, (byte)0xD4, (byte)0xB8};	 
	private final static byte SECP256K1_R[] = 
		{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* R = N */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, (byte)0xBA, (byte)0xAE, (byte)0xDC, (byte)0xE6,
		 (byte)0xAF, (byte)0x48, (byte)0xA0, (byte)0x3B, (byte)0xBF, (byte)0xD2, (byte)0x5E, (byte)0x8C, (byte)0xD0, (byte)0x36,
		 (byte)0x41, (byte)0x41};	
	private final static short SECP256K1_K = (short)0x01;
	
	/** SECP256R1 */
	private static final byte SECP256R1_FP[] = 
	    {(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00,    /* P = FP */
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		 (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
         (byte)0xff, (byte)0xff};
	private static final byte SECP256R1_A[] = {
         (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00,    /* A */
         (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
         (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
         (byte)0xff, (byte)0xfc};
	private static final byte SECP256R1_B[] = {
         (byte)0x5a, (byte)0xc6, (byte)0x35, (byte)0xd8, (byte)0xaa, (byte)0x3a, (byte)0x93, (byte)0xe7, (byte)0xb3, (byte)0xeb,    /* B */
         (byte)0xbd, (byte)0x55, (byte)0x76, (byte)0x98, (byte)0x86, (byte)0xbc, (byte)0x65, (byte)0x1d, (byte)0x06, (byte)0xb0, 
         (byte)0xcc, (byte)0x53, (byte)0xb0, (byte)0xf6, (byte)0x3b, (byte)0xce, (byte)0x3c, (byte)0x3e, (byte)0x27, (byte)0xd2,
         (byte)0x60, (byte)0x4b};
	private static final byte SECP256R1_G[] = {
         (byte)0x04, (byte)0x6b, (byte)0x17, (byte)0xd1, (byte)0xf2, (byte)0xe1, (byte)0x2c, (byte)0x42, (byte)0x47, (byte)0xf8,    /* G */
         (byte)0xbc, (byte)0xe6, (byte)0xe5, (byte)0x63, (byte)0xa4, (byte)0x40, (byte)0xf2, (byte)0x77, (byte)0x03, (byte)0x7d, 
         (byte)0x81, (byte)0x2d, (byte)0xeb, (byte)0x33, (byte)0xa0, (byte)0xf4, (byte)0xa1, (byte)0x39, (byte)0x45, (byte)0xd8, 
         (byte)0x98, (byte)0xc2, (byte)0x96, (byte)0x4f, (byte)0xe3, (byte)0x42, (byte)0xe2, (byte)0xfe, (byte)0x1a, (byte)0x7f, 
         (byte)0x9b, (byte)0x8e, (byte)0xe7, (byte)0xeb, (byte)0x4a, (byte)0x7c, (byte)0x0f, (byte)0x9e, (byte)0x16, (byte)0x2b, 
         (byte)0xce, (byte)0x33, (byte)0x57, (byte)0x6b, (byte)0x31, (byte)0x5e, (byte)0xce, (byte)0xcb, (byte)0xb6, (byte)0x40, 
         (byte)0x68, (byte)0x37, (byte)0xbf, (byte)0x51, (byte)0xf5};
	private static final byte SECP256R1_R[] = {
         (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xff, (byte)0xff,    /* R = N */
         (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xbc, (byte)0xe6, (byte)0xfa, (byte)0xad, 
         (byte)0xa7, (byte)0x17, (byte)0x9e, (byte)0x84, (byte)0xf3, (byte)0xb9, (byte)0xca, (byte)0xc2, (byte)0xfc, (byte)0x63,
         (byte)0x25, (byte)0x51};
	private static final byte SECP256R1_K = (byte)0x01;
	
	/** SECP384R1 */
	private static final byte SECP384R1_FP[] =
		{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* P = FP */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFE, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
    private static final byte SECP384R1_A[] =
		{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* A */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFE, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
		 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC};
	private static final byte SECP384R1_B[] =
		{(byte)0xB3, (byte)0x31, (byte)0x2F, (byte)0xA7, (byte)0xE2, (byte)0x3E, (byte)0xE7, (byte)0xE4, (byte)0x98, (byte)0x8E,	/* B */
		 (byte)0x05, (byte)0x6B, (byte)0xE3, (byte)0xF8, (byte)0x2D, (byte)0x19, (byte)0x18, (byte)0x1D, (byte)0x9C, (byte)0x6E,
		 (byte)0xFE, (byte)0x81, (byte)0x41, (byte)0x12, (byte)0x03, (byte)0x14, (byte)0x08, (byte)0x8F, (byte)0x50, (byte)0x13,
		 (byte)0x87, (byte)0x5A, (byte)0xC6, (byte)0x56, (byte)0x39, (byte)0x8D, (byte)0x8A, (byte)0x2E, (byte)0xD1, (byte)0x9D,
		 (byte)0x2A, (byte)0x85, (byte)0xC8, (byte)0xED, (byte)0xD3, (byte)0xEC, (byte)0x2A, (byte)0xEF};	 
	private static final byte SECP384R1_G[] =
		{(byte)0x04, (byte)0xAA, (byte)0x87, (byte)0xCA, (byte)0x22, (byte)0xBE, (byte)0x8B, (byte)0x05, (byte)0x37, (byte)0x8E,	/* G */
		 (byte)0xB1, (byte)0xC7, (byte)0x1E, (byte)0xF3, (byte)0x20, (byte)0xAD, (byte)0x74, (byte)0x6E, (byte)0x1D, (byte)0x3B, 
		 (byte)0x62, (byte)0x8B, (byte)0xA7, (byte)0x9B, (byte)0x98, (byte)0x59, (byte)0xF7, (byte)0x41, (byte)0xE0, (byte)0x82, 
		 (byte)0x54, (byte)0x2A, (byte)0x38, (byte)0x55, (byte)0x02, (byte)0xF2, (byte)0x5D, (byte)0xBF, (byte)0x55, (byte)0x29, 
		 (byte)0x6C, (byte)0x3A, (byte)0x54, (byte)0x5E, (byte)0x38, (byte)0x72, (byte)0x76, (byte)0x0A, (byte)0xB7, (byte)0x36, 
		 (byte)0x17, (byte)0xDE, (byte)0x4A, (byte)0x96, (byte)0x26, (byte)0x2C, (byte)0x6F, (byte)0x5D, (byte)0x9E, (byte)0x98, 
		 (byte)0xBF, (byte)0x92, (byte)0x92, (byte)0xDC, (byte)0x29, (byte)0xF8, (byte)0xF4, (byte)0x1D, (byte)0xBD, (byte)0x28, 
		 (byte)0x9A, (byte)0x14, (byte)0x7C, (byte)0xE9, (byte)0xDA, (byte)0x31, (byte)0x13, (byte)0xB5, (byte)0xF0, (byte)0xB8, 
		 (byte)0xC0, (byte)0x0A, (byte)0x60, (byte)0xB1, (byte)0xCE, (byte)0x1D, (byte)0x7E, (byte)0x81, (byte)0x9D, (byte)0x7A, 
		 (byte)0x43, (byte)0x1D, (byte)0x7C, (byte)0x90, (byte)0xEA, (byte)0x0E, (byte)0x5F};
	private static final byte SECP384R1_R[] =
		{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* R = N */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xC7, (byte)0x63, (byte)0x4D, (byte)0x81, (byte)0xF4, (byte)0x37,
		 (byte)0x2D, (byte)0xDF, (byte)0x58, (byte)0x1A, (byte)0x0D, (byte)0xB2, (byte)0x48, (byte)0xB0, (byte)0xA7, (byte)0x7A,
		 (byte)0xEC, (byte)0xEC, (byte)0x19, (byte)0x6A, (byte)0xCC, (byte)0xC5, (byte)0x29, (byte)0x73};
	private static final byte SECP384R1_K = (byte)0x01;
	
	/** SECP521R1 */
	private static final byte SECP521R1_FP[] =
		{(byte)0x01, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* P = FP */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
	private static final byte SECP521R1_A[] =
		{(byte)0x01, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* A */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC};
	private static final byte SECP521R1_B[] =
		{(byte)0x00, (byte)0x51, (byte)0x95, (byte)0x3E, (byte)0xB9, (byte)0x61, (byte)0x8E, (byte)0x1C, (byte)0x9A, (byte)0x1F,	/* B */
		 (byte)0x92, (byte)0x9A, (byte)0x21, (byte)0xA0, (byte)0xB6, (byte)0x85, (byte)0x40, (byte)0xEE, (byte)0xA2, (byte)0xDA,
		 (byte)0x72, (byte)0x5B, (byte)0x99, (byte)0xB3, (byte)0x15, (byte)0xF3, (byte)0xB8, (byte)0xB4, (byte)0x89, (byte)0x91,
		 (byte)0x8E, (byte)0xF1, (byte)0x09, (byte)0xE1, (byte)0x56, (byte)0x19, (byte)0x39, (byte)0x51, (byte)0xEC, (byte)0x7E,
		 (byte)0x93, (byte)0x7B, (byte)0x16, (byte)0x52, (byte)0xC0, (byte)0xBD, (byte)0x3B, (byte)0xB1, (byte)0xBF, (byte)0x07,
		 (byte)0x35, (byte)0x73, (byte)0xDF, (byte)0x88, (byte)0x3D, (byte)0x2C, (byte)0x34, (byte)0xF1, (byte)0xEF, (byte)0x45,
		 (byte)0x1F, (byte)0xD4, (byte)0x6B, (byte)0x50, (byte)0x3F, (byte)0x00};	
	private static final byte SECP521R1_G[] =
		{(byte)0x04, (byte)0x00, (byte)0xC6, (byte)0x85, (byte)0x8E, (byte)0x06, (byte)0xB7, (byte)0x04, (byte)0x04, (byte)0xE9,	/* G */
		 (byte)0xCD, (byte)0x9E, (byte)0x3E, (byte)0xCB, (byte)0x66, (byte)0x23, (byte)0x95, (byte)0xB4, (byte)0x42, (byte)0x9C,
		 (byte)0x64, (byte)0x81, (byte)0x39, (byte)0x05, (byte)0x3F, (byte)0xB5, (byte)0x21, (byte)0xF8, (byte)0x28, (byte)0xAF,
		 (byte)0x60, (byte)0x6B, (byte)0x4D, (byte)0x3D, (byte)0xBA, (byte)0xA1, (byte)0x4B, (byte)0x5E, (byte)0x77, (byte)0xEF,
		 (byte)0xE7, (byte)0x59, (byte)0x28, (byte)0xFE, (byte)0x1D, (byte)0xC1, (byte)0x27, (byte)0xA2, (byte)0xFF, (byte)0xA8,
		 (byte)0xDE, (byte)0x33, (byte)0x48, (byte)0xB3, (byte)0xC1, (byte)0x85, (byte)0x6A, (byte)0x42, (byte)0x9B, (byte)0xF9,
		 (byte)0x7E, (byte)0x7E, (byte)0x31, (byte)0xC2, (byte)0xE5, (byte)0xBD, (byte)0x66, (byte)0x01, (byte)0x18, (byte)0x39,
		 (byte)0x29, (byte)0x6A, (byte)0x78, (byte)0x9A, (byte)0x3B, (byte)0xC0, (byte)0x04, (byte)0x5C, (byte)0x8A, (byte)0x5F,
		 (byte)0xB4, (byte)0x2C, (byte)0x7D, (byte)0x1B, (byte)0xD9, (byte)0x98, (byte)0xF5, (byte)0x44, (byte)0x49, (byte)0x57,
		 (byte)0x9B, (byte)0x44, (byte)0x68, (byte)0x17, (byte)0xAF, (byte)0xBD, (byte)0x17, (byte)0x27, (byte)0x3E, (byte)0x66,
		 (byte)0x2C, (byte)0x97, (byte)0xEE, (byte)0x72, (byte)0x99, (byte)0x5E, (byte)0xF4, (byte)0x26, (byte)0x40, (byte)0xC5,
		 (byte)0x50, (byte)0xB9, (byte)0x01, (byte)0x3F, (byte)0xAD, (byte)0x07, (byte)0x61, (byte)0x35, (byte)0x3C, (byte)0x70,
		 (byte)0x86, (byte)0xA2, (byte)0x72, (byte)0xC2, (byte)0x40, (byte)0x88, (byte)0xBE, (byte)0x94, (byte)0x76, (byte)0x9F,
		 (byte)0xD1, (byte)0x66, (byte)0x50};
	private static final byte SECP521R1_R[] =
		{(byte)0x01, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,	/* R = N */
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
		 (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFA, (byte)0x51, (byte)0x86, (byte)0x87, (byte)0x83, (byte)0xBF, (byte)0x2F,
		 (byte)0x96, (byte)0x6B, (byte)0x7F, (byte)0xCC, (byte)0x01, (byte)0x48, (byte)0xF7, (byte)0x09, (byte)0xA5, (byte)0xD0,
		 (byte)0x3B, (byte)0xB5, (byte)0xC9, (byte)0xB8, (byte)0x89, (byte)0x9C, (byte)0x47, (byte)0xAE, (byte)0xBB, (byte)0x6F,
		 (byte)0xB7, (byte)0x1E, (byte)0x91, (byte)0x38, (byte)0x64, (byte)0x09}; 
	private static final byte SECP521R1_K = (byte)0x01;


    static void setCurveParameters(byte curveType, ECKey key) {
        
    	try {
    		
    		switch (curveType) {
		        case IoTSafeDeclarations.ECC_CURVE_secp224k1: 
		        	key.setA(SECP224K1_A, (short)0, (short)SECP224K1_A.length);
		            key.setB(SECP224K1_B, (short)0, (short)SECP224K1_B.length);
		            key.setFieldFP(SECP224K1_FP, (short)0, (short)SECP224K1_FP.length);
		            key.setG(SECP224K1_G, (short)0, (short)SECP224K1_G.length);
		            key.setR(SECP224K1_R, (short)0, (short)SECP224K1_R.length);
		            key.setK(SECP224K1_K);
		            break;
		        case IoTSafeDeclarations.ECC_CURVE_secp224r1: 
		        	key.setA(SECP224R1_A, (short)0, (short)SECP224R1_A.length);
		            key.setB(SECP224R1_B, (short)0, (short)SECP224R1_B.length);
		            key.setFieldFP(SECP224R1_FP, (short)0, (short)SECP224R1_FP.length);
		            key.setG(SECP224R1_G, (short)0, (short)SECP224R1_G.length);
		            key.setR(SECP224R1_R, (short)0, (short)SECP224R1_R.length);
		            key.setK(SECP224R1_K);
		            break;
		        case IoTSafeDeclarations.ECC_CURVE_secp256k1: 
		        	key.setA(SECP256K1_A, (short)0, (short)SECP256K1_A.length);
		            key.setB(SECP256K1_B, (short)0, (short)SECP256K1_B.length);
		            key.setFieldFP(SECP256K1_FP, (short)0, (short)SECP256K1_FP.length);
		            key.setG(SECP256K1_G, (short)0, (short)SECP256K1_G.length);
		            key.setR(SECP256K1_R, (short)0, (short)SECP256K1_R.length);
		            key.setK(SECP256K1_K);
		            break;
		        case IoTSafeDeclarations.ECC_CURVE_secp256r1: 
		        	key.setA(SECP256R1_A, (short)0, (short)SECP256R1_A.length);
		            key.setB(SECP256R1_B, (short)0, (short)SECP256R1_B.length);
		            key.setFieldFP(SECP256R1_FP, (short)0, (short)SECP256R1_FP.length);
		            key.setG(SECP256R1_G, (short)0, (short)SECP256R1_G.length);
		            key.setR(SECP256R1_R, (short)0, (short)SECP256R1_R.length);
		            key.setK(SECP256R1_K);
		            break;
		        case IoTSafeDeclarations.ECC_CURVE_secp384r1:
		        	key.setA(SECP384R1_A, (short)0, (short)SECP384R1_A.length);
		            key.setB(SECP384R1_B, (short)0, (short)SECP384R1_B.length);
		            key.setFieldFP(SECP384R1_FP, (short)0, (short)SECP384R1_FP.length);
		            key.setG(SECP384R1_G, (short)0, (short)SECP384R1_G.length);
		            key.setR(SECP384R1_R, (short)0, (short)SECP384R1_R.length);
		            key.setK(SECP384R1_K);
		            break;
		        case IoTSafeDeclarations.ECC_CURVE_secp521r1:
		        	key.setA(SECP521R1_A, (short)0, (short)SECP521R1_A.length);
		            key.setB(SECP521R1_B, (short)0, (short)SECP521R1_B.length);
		            key.setFieldFP(SECP521R1_FP, (short)0, (short)SECP521R1_FP.length);
		            key.setG(SECP521R1_G, (short)0, (short)SECP521R1_G.length);
		            key.setR(SECP521R1_R, (short)0, (short)SECP521R1_R.length);
		            key.setK(SECP521R1_K);
		            break;
		        default:
		        	ISOException.throwIt(IoTSafeDeclarations.SW_GENERIC_ERROR);
			}       
        }
        catch(Exception e) {
        	ISOException.throwIt(IoTSafeDeclarations.SW_GENERIC_ERROR);
        }
    }
	
	static byte getKeyPairAlgorithm(byte keyType) {
		
		switch (keyType) {
			case IoTSafeDeclarations.KEY_TYPE_RSA_2048:        	
	    		return KeyPair.ALG_RSA;       	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_224:        	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_256:        	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_384:        	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_521:        	
	        	return KeyPair.ALG_EC_FP;
	        default:
	        	return IoTSafeDeclarations.KEY_TYPE_UNKNOWN;
		}
	}
	
	static byte getPublicKeyType(byte keyType) {
		
		switch (keyType) {
			case IoTSafeDeclarations.KEY_TYPE_RSA_2048:        	
	    		return KeyBuilder.TYPE_RSA_PUBLIC;     	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_224:        	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_256:        	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_384:        	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_521:        	
	        	return KeyBuilder.TYPE_EC_FP_PUBLIC;
	        default:
	        	return IoTSafeDeclarations.KEY_TYPE_UNKNOWN;
		}
	}
	
	static byte getPrivateKeyType(byte keyType) {
		
		switch (keyType) {
			case IoTSafeDeclarations.KEY_TYPE_RSA_2048:        	
	    		return KeyBuilder.TYPE_RSA_PRIVATE;       	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_224:        	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_256:        	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_384:        	
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_521:        	
	        	return KeyBuilder.TYPE_EC_FP_PRIVATE;
	        default:
	        	return IoTSafeDeclarations.KEY_TYPE_UNKNOWN;
		}
	}
	
	static byte getSecretKeyType(byte keyType) {
		
		switch (keyType) {
			case IoTSafeDeclarations.KEY_TYPE_AES_128:        	
	        case IoTSafeDeclarations.KEY_TYPE_AES_256:        	
	        	return KeyBuilder.TYPE_AES;
	        default:
	        	return IoTSafeDeclarations.KEY_TYPE_UNKNOWN;
		}
	}
	
	static byte getCipherAlgorithm(byte cipherType) {
		
		switch (cipherType) {
			case IoTSafeDeclarations.CIPHER_RSA_2048_NOPAD:        	
	    		return Cipher.ALG_RSA_PKCS1;
	        case IoTSafeDeclarations.CIPHER_AES_128_CBC_NOPAD:     
	        	return Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;
	        case IoTSafeDeclarations.CIPHER_AES_128_ECB_NOPAD:   
	        	return Cipher.ALG_AES_BLOCK_128_ECB_NOPAD;
	        default:
	        	return IoTSafeDeclarations.CIPHER_TYPE_UNKNOWN;
		}
	}
	
	
	static short getKeySize(byte keyType) {
		
		switch (keyType) {
			case IoTSafeDeclarations.KEY_TYPE_RSA_2048:        	
	    		return KeyBuilder.LENGTH_RSA_2048;
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_224:
	        	return KeyBuilder.LENGTH_EC_FP_224;
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_256:  
	        	return KeyBuilder.LENGTH_EC_FP_256;
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_384:  
	        	return KeyBuilder.LENGTH_EC_FP_384;
	        case IoTSafeDeclarations.KEY_TYPE_EC_FP_521:        	
	        	// fix for IFX cards
	        	//return KeyBuilder.LENGTH_EC_FP_521;
	        	return (short)528;
	        case IoTSafeDeclarations.KEY_TYPE_AES_128:        	
	        	return KeyBuilder.LENGTH_AES_128;
	        case IoTSafeDeclarations.KEY_TYPE_AES_256:        	
	        	return KeyBuilder.LENGTH_AES_256;
	        default:
	        	return IoTSafeDeclarations.KEY_SIZE_UNKNOWN;
		}
	}
	
	static void checkKeyAndCurveType(byte keyType, byte curveType) {
	
		// check key type and curve type combinations
		if(keyType == IoTSafeDeclarations.KEY_TYPE_RSA_2048) {
			if(curveType != IoTSafeDeclarations.ECC_CURVE_UNKNOWN) {
				ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
			}
		}
		else if(keyType == IoTSafeDeclarations.KEY_TYPE_EC_FP_224) {
			if((curveType != IoTSafeDeclarations.ECC_CURVE_secp224k1) &&
			   (curveType != IoTSafeDeclarations.ECC_CURVE_secp224r1)) {
				ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
			}
		}
		else if(keyType == IoTSafeDeclarations.KEY_TYPE_EC_FP_256) {
			if((curveType != IoTSafeDeclarations.ECC_CURVE_secp256k1) &&
			   (curveType != IoTSafeDeclarations.ECC_CURVE_secp256r1)) {
				ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
			}
		}
		else if(keyType == IoTSafeDeclarations.KEY_TYPE_EC_FP_384) {
			if(curveType != IoTSafeDeclarations.ECC_CURVE_secp384r1) {
				ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
			}
		}
		else if(keyType == IoTSafeDeclarations.KEY_TYPE_EC_FP_521) {
			if(curveType != IoTSafeDeclarations.ECC_CURVE_secp521r1) {
				ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
			}
		}
		else {
			ISOException.throwIt(IoTSafeDeclarations.SW_P1P2_NOT_SUPPORTED);
		}
	}

}
