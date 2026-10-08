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
#include <vector>
#include <winscard.h>
#include <string>
#include <map>

typedef std::vector<std::wstring> CReaderList;

class FileLogger;

/**
*	Class for direct driver communication
*/
class DriverDirect {
public:
	DriverDirect();
	virtual ~DriverDirect();

	int		sendDisconnectNow();
	int		sendStartDiscovery();
	int		sendFobAddress(const std::string& adr);
	int		sendDataToDriver(const std::string& data);
	LONG	getGetFobAddress(std::string &adr);
	int		transmit(const std::string& data, std::string& response);
	int		applyConfig(std::map<std::string, std::string>& config);

	void	setLogger(FileLogger* obj) noexcept {
		this->logger = obj;
	}
	void	setMode(int value);
	void	setConnectProtocol(int value);
	int		setTransmitProtocol(int value);
	void	setControlProtocol(const std::string& value);
	int		sendControl(SCARDHANDLE hCard, DWORD dwControlCode, const std::string& data, std::string& response);

	void	setDeviceName(const std::wstring& name);
	void	setDeviceNameA(const std::string& name);

private:
	std::wstring findReader(CReaderList* readers, const wchar_t* name);
	int listReaders(SCARDCONTEXT hSC, CReaderList* readers);

	FileLogger* logger;
	// used in SCardConnect
	int mMode, mConnectProtocol;

	// used in SCardTransmit
	LPCSCARD_IO_REQUEST mTransmitProtocol;

	// used in direct SCardControl (PROTOCOL)
	std::string mContolProtocol;
	bool mControlProtocolSet;

	std::wstring deviceName;
};

