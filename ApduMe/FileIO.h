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

