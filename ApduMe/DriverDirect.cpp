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

#include "DriverDirect.h"

#include "FileLogger.h"
#include "Utils.h"

#define TRANSMIT_PROTOCOL_T0    0
#define TRANSMIT_PROTOCOL_T1    1
#define TRANSMIT_PROTOCOL_RAW   2
#define OUT_BUFFER_SIZE         64


DriverDirect::DriverDirect() : logger(nullptr), 
        mMode(SCARD_SHARE_DIRECT), 
        mConnectProtocol(0),
        mTransmitProtocol(SCARD_PCI_T0),
        mContolProtocol(""),
        mControlProtocolSet(false) {
}

DriverDirect::~DriverDirect() {
}

/**
*   @return 0 if success
*/
int DriverDirect::listReaders(SCARDCONTEXT hSC, CReaderList* readers) {
    bool ok = readers->empty();
    if (!ok)
        return 1;

    // will auto allocate memory for the list of readers
    TCHAR* pszReaderList = nullptr;
    DWORD len = SCARD_AUTOALLOCATE;

    LONG ret = SCardListReaders(
        hSC,
        NULL,           // groups, using null will list all readers in the system
        (LPWSTR)&pszReaderList, // pointer where to store the readers
        &len);          // will return the length of characters
                        // in the reader list buffer

    if (ret == SCARD_S_SUCCESS && pszReaderList!=nullptr) {
        TCHAR* pszReader = pszReaderList;
        while (*pszReader) {
            readers->push_back(pszReader);
            
            LOG(Utils::ws2s(pszReader).c_str());
            pszReader += _tcslen(pszReader) + 1;
        }

        // free the memory
        ret = SCardFreeMemory(hSC, pszReaderList);
    }
    else {
        return 2;
    }
    return 0;
}

int DriverDirect::sendDisconnectNow() {
    return sendDataToDriver("DISCONNECTNOW");
}

int DriverDirect::sendStartDiscovery() {
    return sendDataToDriver("STARTDISCOVERY");
}

int DriverDirect::sendFobAddress(const std::string& adr) {
    return sendDataToDriver("SETADR." + adr);
}

int DriverDirect::sendDataToDriver(const std::string& data) {
	LOG("DriverDirect::sendDataToDriver");

	LONG ret;
    const char* cmd = nullptr;
    SCARDHANDLE     hCardHandle;
    LONG            lReturn;
    DWORD           dwAP;
    SCARDCONTEXT    hSC;
    int result = 0;

    // Establish the context.
    lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
        NULL,
        NULL,
        &hSC);
    if (SCARD_S_SUCCESS != lReturn) {
        LOG("Failed SCardEstablishContext");
        return -1;
    }
    LOG("SCardEstablishContext OK");

    CReaderList readers;
    std::wstring myReader;
    ret = listReaders(hSC, &readers);
    if (ret != 0) {
        LOG("listReaders Failed");
        result = ret;
        goto fin;
    }

    myReader = findReader(&readers, deviceName.c_str());
    if (myReader.empty()) {
        LOG("required device not found in system..");
        goto fin;
    }

    lReturn = SCardConnect(hSC,
        myReader.c_str(),
        mMode,           //SCARD_SHARE_DIRECT, 
        mConnectProtocol,

        &hCardHandle,
        &dwAP);

    if (SCARD_S_SUCCESS != lReturn) {
        LOG2("Failed SCardConnect ", lReturn);
        result = -2;
        goto fin;
    }
    LOG("SCardConnect OK");

    // Use the connection.
    // Display the active protocol.
   switch (dwAP) {
    case SCARD_PROTOCOL_T0:
        LOG("Active protocol T0");
        break;

    case SCARD_PROTOCOL_T1:
        LOG("Active protocol T1");
        break;

    case SCARD_PROTOCOL_UNDEFINED:
    default:
        LOG("Active protocol unnegotiated or unknown");
        break;
    }

    cmd = data.c_str();
	ret = SCardSetAttrib(
        hCardHandle,
		100,
		(LPCBYTE)cmd,
		(DWORD)strlen(cmd)
	);
	LOG2("SCardSetAttrib ret", ret);

    if (ret != SCARD_S_SUCCESS) {
       // LOG("Can not apply information to driver about assigned key-fob");

    }

	ret = SCardDisconnect(hCardHandle, SCARD_LEAVE_CARD);
	LOG2("SCardDisconnect ret", ret);

fin:
    SCardReleaseContext(hSC);
	return result;
}

std::wstring DriverDirect::findReader(CReaderList* readers, const wchar_t* nameReader) {
    for (size_t i = 0; i < readers->size(); i++) {
        const std::wstring& name1 = readers->at(i);
        if (name1.find(nameReader) != std::wstring::npos)
            return name1;
    }
    // Not found. The previous version returned nullptr here, which built an
    // MFC string from a null pointer and tripped an ATL assertion; callers now
    // test the result with empty().
    return std::wstring();
}


LONG DriverDirect::getGetFobAddress(std::string& adr) {
    LONG ret = 0L;
    DWORD ln = 64;
    SCARDHANDLE     hCardHandle;
    DWORD           dwAP;
    SCARDCONTEXT    hSC;

    // Establish the context.
    ret = SCardEstablishContext(SCARD_SCOPE_USER,
        NULL,
        NULL,
        &hSC);

    if (SCARD_S_SUCCESS != ret) {
        LOG("Failed SCardEstablishContext");
        return ret;
    }
    LOG("SCardEstablishContext OK");

    CReaderList readers;
    listReaders(hSC, &readers);

    std::wstring myReader = findReader(&readers, L"StarSign Key Fob");
    if (myReader.empty()) {
        LOG("no target device found in system.. OK");
        goto fin;
    }

    ret = SCardConnect(hSC,
        myReader.c_str(),
        mMode, //SCARD_SHARE_DIRECT,
        mConnectProtocol,
        &hCardHandle,
        &dwAP);

    if (SCARD_S_SUCCESS != ret) {
        LOG2("Failed SCardConnect ", ret);
        goto fin;
    }
    LOG("SCardConnect OK");

    char buffer[64];
    memset(buffer, 0, 64);
    ret = SCardGetAttrib(
        hCardHandle,
        0xA00B,
        (LPBYTE)buffer,
        &ln
    );

    LOG2("SCardSetAttrib ret", ret);
    if (ret == SCARD_S_SUCCESS) {
        if (strlen(buffer) == 1 && buffer[0] == '0') {
            adr = "";
        }
        else {
            adr.assign(buffer, strlen(buffer));
        }
        LOG("adr=" +adr );

    }
    else {
        LOG("Can not retrieve information about assigned key-fob");
    }

    ret = SCardDisconnect(hCardHandle, SCARD_LEAVE_CARD);
    LOG2("SCardDisconnect ret", ret);

fin:
    SCardReleaseContext(hSC);
    return ret;
}

int DriverDirect::transmit(const std::string& data, std::string& response) {
    LONG ret;
    const char* cmd = nullptr;
    SCARDHANDLE     hCardHandle;
    LONG            lReturn;
    DWORD           dwAP;
    SCARDCONTEXT    hSC;
    DWORD recvLength = 4096;
    byte recvBuffer[4096];
    int result = 0;

    // Establish the context.
    lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
        NULL,
        NULL,
        &hSC);
    if (SCARD_S_SUCCESS != lReturn) {
        LOG("Failed SCardEstablishContext");
        return -1;
    }

    CReaderList readers;
    listReaders(hSC, &readers);

    std::wstring myReader = findReader(&readers, deviceName.c_str());
    if (myReader.empty()) {
        LOG("required reader not found in system.. ");
        result = -2;
        goto fin;
    }
    LOG(std::string("Found target device: ") + Utils::ws2s(myReader));

    lReturn = SCardConnect(hSC,
        myReader.c_str(),
        mMode, 
        mConnectProtocol,
        &hCardHandle,
        &dwAP);

    if (SCARD_S_SUCCESS != lReturn) {
        LOG2("Failed SCardConnect ", lReturn);
        result = -3; 
        goto fin;
    }

    // Use the connection.
    // Display the active protocol.
    switch (dwAP) {
        case SCARD_PROTOCOL_T0:
 //           LOG("Active protocol T0");
            break;

        case SCARD_PROTOCOL_T1:
//            LOG("Active protocol T1");
            break;

        case SCARD_PROTOCOL_UNDEFINED:
        default:
 //           LOG("Active protocol unnegotiated or unknown");
            break;
    }

    if (mControlProtocolSet) {
        std::string response;
        int result = this->sendControl(hCardHandle, 
            IOCTL_SMARTCARD_SET_PROTOCOL, 
            mContolProtocol,
            response);

        if (result == SCARD_S_SUCCESS) {
            std::string responseHex = Utils::bin2hex(response);
        }
    }

    cmd = data.c_str();
    ret = SCardTransmit(
            hCardHandle,
            mTransmitProtocol, //  SCARD_PCI_T0, SCARD_PCI_T1, and SCARD_PCI_RAW
            (const byte*)cmd,
            (DWORD)data.size(),
            NULL,
            recvBuffer,
            &recvLength
    ); 

    if (ret != SCARD_S_SUCCESS) {
        LOG("Can not apply information to driver about assigned key-fob");
    }
    else {
        response.assign((char*)recvBuffer, recvLength);
    }

    ret = SCardDisconnect(hCardHandle, SCARD_LEAVE_CARD);

fin:
    SCardReleaseContext(hSC);
    return result;
}

int DriverDirect::applyConfig(std::map<std::string, std::string>& config) {
    std::string value = Utils::getMapValue(config, "mode");
    if (!value.empty()) {
        if (!value.compare("direct")) {
            setMode(SCARD_SHARE_DIRECT);
        } else
        if (!value.compare("shared")) {
            setMode(SCARD_SHARE_SHARED);
        } else 
        if (!value.compare("exclusive")) {
            setMode(SCARD_SHARE_EXCLUSIVE);
        }
        else {
            logger->log("not recognized value for 'mode'");
            return -1;
        }
    }

    value = Utils::getMapValue(config, "connect-protocol");
    if (!value.empty()) {
        if (!value.compare("0")) {
            setConnectProtocol(0);
        } else 
        if (!value.compare("T0")) {
            setConnectProtocol(SCARD_PROTOCOL_T0);
        } else
        if (!value.compare("T1")) {
            setConnectProtocol(SCARD_PROTOCOL_T1);
        } else 
        if (!value.compare("T0T1")) {
            setConnectProtocol(SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1);
        }
    }
    value = Utils::getMapValue(config, "transmit-protocol");
    if (!value.empty()) {
        if (!value.compare("T0")) {
            setTransmitProtocol(TRANSMIT_PROTOCOL_T0);
        } else
        if (!value.compare("T1"))
        {
            setTransmitProtocol(TRANSMIT_PROTOCOL_T1);
        } else
        if (!value.compare("RAW"))
        {
            setTransmitProtocol(TRANSMIT_PROTOCOL_RAW);
        }
    }
    value = Utils::getMapValue(config, "control-protocol");
    if (!value.empty()) {
        setControlProtocol(value);
    }

    value = Utils::getMapValue(config, "device");
    if (!value.empty()) {
        setDeviceNameA(value);
    }

    return 0;
}

void DriverDirect::setMode(int value) {
    LOG2("setMode", value);
    this->mMode = value;
}

void DriverDirect::setConnectProtocol(int value) {
    LOG2("setConnectProtocol", value);
    this->mConnectProtocol = value;
}

int DriverDirect::setTransmitProtocol(int value) {
    int result = 0;
    LOG2("setTransmitProtocol", value);
    switch (value) {
        case TRANSMIT_PROTOCOL_T0:
            this->mTransmitProtocol = SCARD_PCI_T0;
            break;
        case TRANSMIT_PROTOCOL_T1:
            this->mTransmitProtocol = SCARD_PCI_T1;
            break;
        case TRANSMIT_PROTOCOL_RAW:
            this->mTransmitProtocol = SCARD_PCI_RAW;
            break;
        default:
            LOG2("Not correct TransmitProtocol: ", value);
            result = 1;
    }
    return result;
}

/**
* Set control protocol
* @param value [IN] - control protocol
*/
void DriverDirect::setControlProtocol(const std::string& value) {
    this->mControlProtocolSet = true;
    this->mContolProtocol = Utils::hex2bin(value);
}

int DriverDirect::sendControl(  SCARDHANDLE hCard, 
                                DWORD dwControlCode, 
                                const std::string& data, 
                                std::string& response) {
    byte        lpOutBuffer[OUT_BUFFER_SIZE];
    DWORD       dwBytesReturned;

    memset(lpOutBuffer, 0, OUT_BUFFER_SIZE);
    LONG ret =  SCardControl(hCard,
            dwControlCode,
            data.c_str(),
            (DWORD)data.size(),
            lpOutBuffer,
            OUT_BUFFER_SIZE,
            &dwBytesReturned);

    if (dwBytesReturned > 0) {
        response.assign((const char*)lpOutBuffer, dwBytesReturned);
    }

    return ret;
}

void DriverDirect::setDeviceName(const std::wstring& name) {
    LOG("DriverDirect::setDeviceName " + Utils::ws2s(name));

    this->deviceName = name;
}


void DriverDirect::setDeviceNameA(const std::string& name) {
    LOG("DriverDirect::setDeviceName [" + name +"]");

    this->deviceName = Utils::s2ws(name);
}