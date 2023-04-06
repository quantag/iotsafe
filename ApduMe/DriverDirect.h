#pragma once

#include "stdafx.h"
#include <vector>
#include <winscard.h>
#include <string>
#include <map>

typedef std::vector<CString> CReaderList;

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
	CString findReader(CReaderList* readers, const wchar_t* name);
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

