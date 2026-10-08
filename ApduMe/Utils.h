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

#include "stdafx.h"

#include <string>
#include <map>
#include <vector>

typedef std::map<std::string, std::string> MapStrStr;

class Utils {
public:
	static std::string	intToHexString(int value);
	static ErrCode		loadFileW(const std::wstring& fileName, std::string& result);
	static byte*		loadFileW(const wchar_t* fileName, size_t& len);
	static ErrCode		writeFile(const std::wstring& fileName, const std::string& body);
	static std::wstring s2ws(const std::string& value);

	static std::string	charToString(char ch);
	static std::string	bin2hex(const byte* buf, size_t len, bool withSpace = false);
	static std::string	bin2hex(const std::string& data, bool withSpace = false);
	static std::string	vectorToString(const std::vector<unsigned char>& data);
	static std::string	ws2s(const std::wstring& ws);
	static std::string  IntToString(int value);

	static std::string	hex2bin(const std::string& str);
	static bool	loadIniFile(const std::wstring& fileName, std::map<std::string, std::string>& map);
	static std::string getMapValue(MapStrStr& map, const std::string& key);


	static byte* hex2bin0(const std::string& str, size_t& len);
	static std::string format(const char* fmt, ...);
	static std::string format_arg_list(const char* fmt, va_list args);
	static std::string removeChar(const std::string& str1, char c);
	static byte		parseChar_(char p);
	static bool		parseIniFile(const byte* data, size_t len, std::map<std::string, std::string>& map);
	static bool		parseIniFileLine(const std::string& str, std::string& key, std::string& value);
	static bool		getLine(char** begin, const char* end, std::string& rLine);
	static std::string trim(const std::string& str);
	static std::string getBinApdu(const std::string& inputData);
	static std::string apduToolLineToHex(const std::string& inputData);

};

