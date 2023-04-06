#include "Utils.h"

#include <sstream>
#include <fstream>

#include "typedefs.h"

using namespace std;

std::string Utils::intToHexString(int value) {
	std::stringstream stream;
	stream << std::hex << value;
	return std::string(stream.str());
}

std::string Utils::IntToString(int value) {
	return Utils::format("%d", value);
}
/**
*	Load file from disk
*/
ErrCode Utils::loadFileW(const std::wstring& fileName, std::string& result) {
	size_t len = 0U;
	byte* buffer = Utils::loadFileW(fileName.c_str(), len);
	if (!buffer) {
		return eBadFile;
	}
	result.assign((const char*)buffer, len);
	free(buffer);
	return eOk;
}

byte* Utils::loadFileW(const wchar_t* fileName, size_t& len) {
	ifstream::pos_type size;
	byte* memblock = 0;
	len = 0;

	ifstream file(fileName, ios::in | ios::binary | ios::ate);
	if (file.is_open()) {
		size = file.tellg();
		len = (unsigned int)size;
		memblock = new byte[len];
		file.seekg(0, ios::beg);
		file.read((char*)memblock, size);
		file.close();
	}
	return memblock;
}

bool Utils::loadIniFile(const std::wstring& fileName, std::map<std::string, std::string>& map) {
	size_t len = 0;
	byte* data = Utils::loadFileW(fileName.c_str(), len);
	if (len == 0 || !data)
		return false;

	bool ret = parseIniFile(data, len, map);

	delete data;
	return ret;
}

std::string Utils::vectorToString(const std::vector<unsigned char>& data) {
	std::string  str(data.begin(), data.end());
	return str;
}

std::string Utils::bin2hex(const std::string& data, bool withSpace) {
	return Utils::bin2hex((const byte*)data.c_str(), data.size(), withSpace);
}

std::string Utils::bin2hex(const byte* buf, size_t len, bool withSpace) {
	std::string str;
	if (!buf || len == 0U)
		return str;

	for (unsigned int i = 0; i < len; i++)  {
		str += Utils::format("%02x", buf[i]);
		if (withSpace) str += " ";
	}
	return str;
}


std::string Utils::charToString(char ch) 
{
	char tmp[1];
	tmp[0] = ch;
	std::string v(tmp, 1);
	return v;
}

std::string Utils::ws2s(const std::wstring& ws) 
{
	std::string s(ws.begin(), ws.end());
	return s;
}

std::string Utils::format_arg_list(const char* fmt, va_list args) {
	if (!fmt) return "";
	int   result = -1, length = 256;
	char* buffer = 0;
	while (result == -1) {
		if (buffer) delete[] buffer;
		buffer = new char[length + 1];
		memset(buffer, 0, length + 1);
		result = vsnprintf(buffer, length, fmt, args);
		length *= 2;
	}
	std::string s(buffer);
	delete[] buffer;
	return s;
}

std::string Utils::format(const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	std::string s = format_arg_list(fmt, args);
	va_end(args);
	return s;
}

ErrCode Utils::writeFile(const std::wstring& fileName, const std::string& body) {
	FILE* ptr;
	errno_t ret = _wfopen_s(&ptr, fileName.c_str(), L"wb+");
	if (ret != 0) return eFatal;
	fwrite(body.c_str(), 1, body.size(), ptr);
	fclose(ptr);
	return eOk;
}

std::wstring Utils::s2ws(const std::string& value) {
	std::wstring w(value.begin(), value.end());
	return w;
}

// same as hex2bin but std::string as output container of binary data
std::string Utils::hex2bin(const std::string& str) {
	std::string	 str2 = Utils::removeChar(str, ' ');
	std::string	 str3 = Utils::removeChar(str2, '\t');
	str3 = Utils::removeChar(str3, '\r');

	size_t len;
	byte* tmp = hex2bin0(str3, len);
	std::string res;
	res.assign((const char*)tmp, len);
	SAFE_FREE(tmp);
	return res;
}

byte* Utils::hex2bin0(const std::string& str, size_t& len) {
	len = str.length() / 2;
	byte* buf = (byte*)calloc(len, 1);
	size_t ptr = 0;
	for (size_t pos = 0; pos < str.length(); pos += 2) {
		byte b = (parseChar_(str[pos]) << 4) + parseChar_(str[pos + 1]);
		buf[ptr++] = b;
	}
	return buf;
}

std::string	 Utils::removeChar(const std::string& str1, char c) {
	std::string result = "";
	for (size_t i = 0; i < str1.size(); i++) {
		if (str1[i] != c)
			result += str1[i];
	}
	return result;
}

byte Utils::parseChar_(char p) {
	if (p >= '0' && p <= '9')
		return (byte)(p - '0');

	if (p >= 'a' && p <= 'f')
		return 10 + (byte)(p - 'a');

	if (p >= 'A' && p <= 'F')
		return 10 + (byte)(p - 'A');

	return 255;
}

// ret true if OK
bool Utils::parseIniFile(const byte * data, size_t len, std::map<std::string, std::string>&map) {
	if (!data || len == 0)
		return false;

	char* buff = (char*)&data[0];
	char* buffEnd = buff + len;

	std::string line;
	int lineNumber = 1;

	bool bContinue = true;
	do {
		bContinue = getLine(&buff, buffEnd, line);
		if (bContinue || !line.empty()) {
			std::string key;
			std::string value;
			if (!parseIniFileLine(line, key, value)) {
				//LOG(Log::eStream, "config parse error: [%s]", line.c_str());
				return false;
			}
			if (!key.empty())
				map[key] = value;

			lineNumber++;
		}
	} while (bContinue);

	return true;
}

/**
	 parse line [key=value]
	  # is comment
	 return true if OK, false if error

	 if OK: key = key , value = value
*/
bool Utils::parseIniFileLine(const std::string& str, std::string& key, std::string& value) {
	key = "";
	value = "";

	if (str.empty())
		return true; //true;

	if (str[0] == '#') // comment
		return true; // true;

	std::string::size_type pos = str.find_first_of("=");
	if (pos == std::string::npos)
		return false;

	std::string _key = str.substr(0, pos);
	std::string _value = str.substr(pos + 1);

	key = Utils::trim(_key);
	value = Utils::trim(_value);
	return true;
}

/**
	Read one line from config-file buffer.
	return 'true' if end not reached
*/
bool Utils::getLine(char** begin, const char* end, std::string& rLine) {
	rLine.clear();

	char* lineStart = *begin;
	char* lineEnd = lineStart;

	// iterate over valid chars
	while (lineEnd < end && *lineEnd != '\r' && *lineEnd != '\n')
		lineEnd++;

	if (lineEnd != lineStart)
		rLine = std::string(lineStart, lineEnd);

	// skip [\r]\n at the end of line
	if (lineEnd < end && *lineEnd == '\r')
		lineEnd++;

	if (lineEnd < end && *lineEnd == '\n')
		lineEnd++;

	*begin = lineEnd;
	return (lineEnd != end);
}

string Utils::trim(const string& _str) {
	std::string str = _str;
	int i, j, start, end;

	//ltrim
	for (i = 0; (str[i] != 0 && str[i] <= 32); )
		i++;
	start = i;

	//rtrim
	for (i = 0, j = 0; str[i] != 0; i++)
		j = ((str[i] <= 32) ? j + 1 : 0);
	end = i - j;
	str = str.substr(start, end - start);
	return str;
}

/**
*	Get value by key from std::map
*	@return empty string if not found
*/
std::string  Utils::getMapValue(MapStrStr& map, const std::string& key) {
	MapStrStr::iterator it = map.find(key);
	if (it == map.end())
		return "";
	return it->second;
}

std::string Utils::apduToolLineToHex(const std::string& inputData) {
	std::string hexData = "";

	for (int i = 0; i < inputData.size() - 3; i++) {
		char ch = inputData.at(i);
		char ch1 = inputData.at(i + 1);
		char ch2 = inputData.at(i + 2);
		char ch3 = inputData.at(i + 3);

		if (ch == ';') continue;

		if (ch == '0' && ch1 == 'x') {
			hexData += ch2;
			hexData += ch3;

			i += 3;
		}
	}
	return hexData;
}
std::string Utils::getBinApdu(const std::string& inputData) {
	std::string hex = apduToolLineToHex(inputData);
	if (hex.empty()) return "";
	return Utils::hex2bin(hex);
}
