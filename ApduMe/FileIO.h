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

#pragma once

#include "typedefs.h"

#define CONFIG_FILE_NAME	"starsign.dat"

enum FileIOErrCode  {
	eIO_OK = 0,					// = 0x64
	eIO_FILE_OPEN_ERROR = 1,
	eIO_FILE_WRITE_ERROR = 2,
	eIO_TOO_BIG_PAYLOAD = 3,
	eIO_NOT_IO_FILE = 4,
	eIO_PAYLOAD_SIZE_MISMATCH = 5,	// header size != real size, not loaded fully ?
	eIO_CRC_MISMATCH = 6,
	eIO_FILE_DELETE_ERROR = 7
};




class FileIO {
public:
	// low level routines to load/write file
	static int	writeFile(const std::string &fileName, const std::string &data);
	static int	writeFileW(const std::wstring& fileName, const std::string& data);

	static int	readFile(const std::string &fileName, std::string &data);
	static int	readFileW(const std::wstring& fileName, std::string& data);

	static int getGetFobAddress(std::string& adr);
	static void init();

	static std::wstring configFileName;
};

