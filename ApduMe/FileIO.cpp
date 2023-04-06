#include <stdio.h>

#include <iostream>
#include <fstream>
#include <sstream>

#include "FileIO.h"

#include <Shlobj.h>
#include <Knownfolders.h>

std::wstring FileIO::configFileName = L"";


void FileIO::init()  {
	WCHAR* ppszPath;
	HRESULT rr = SHGetKnownFolderPath(
		FOLDERID_PublicLibraries,
		0,
		NULL,
		&ppszPath
	);
	if (ppszPath != NULL) {
		//LOGI("SHGetKnownFolderPath [%ws]", ppszPath);
		configFileName.assign(ppszPath);
		configFileName += L"\\starsign.dat";

		CoTaskMemFree(ppszPath);
	}
	else {
		//LOGI("SHGetKnownFolderPath NULL");

	}
}

/**
*	Simply write binary data block incapsulated in std::string to binary file
*/
int FileIO::writeFile(const std::string &fileName, const std::string &data) {
	FILE* ptr;
	errno_t ret = fopen_s(&ptr, fileName.c_str(), "wb");
	if (ret!=0)
		return ret;

	fwrite(data.c_str(), data.size(), 1, ptr);
	fclose(ptr);

	return 0;
}

int FileIO::writeFileW(const std::wstring& fileName, const std::string& data) {
	FILE* ptr;
	errno_t ret = _wfopen_s(&ptr, fileName.c_str(), L"wb");
	if (ret!=0)
		return ret;

	fwrite(data.c_str(), data.size(), 1, ptr);
	fclose(ptr);

	return 0;
}
/**
*	Simply read binary file to data block incapsulated in std::string
*/
int FileIO::readFile(const std::string& fileName, std::string& data) {
	std::ifstream::pos_type size;
	byte *memblock = 0;

	std::ifstream file(fileName, std::ios::in | std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		return 1;
	}
	
	size = file.tellg();
	size_t len = (unsigned int)size;
	memblock = new byte[len];
	file.seekg(0, std::ios::beg);
	file.read((char*)memblock, size);
	file.close();

	data.assign((const char*)memblock, len);
	free(memblock);

	return 0;
}

int FileIO::readFileW(const std::wstring& fileName, std::string& data) {
	std::ifstream::pos_type size;
	byte* memblock = 0;

	std::ifstream file(fileName, std::ios::in | std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		return 1;
	}

	size = file.tellg();
	size_t len = (unsigned int)size;
	memblock = new byte[len];
	file.seekg(0, std::ios::beg);
	file.read((char*)memblock, size);
	file.close();

	data.assign((const char*)memblock, len);
	free(memblock);

	return 0;
}

int FileIO::getGetFobAddress(std::string& address) {
	int ret = FileIO::readFileW(FileIO::configFileName, address);
	return ret;
}