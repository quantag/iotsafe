#include "FileLogger.h"

#include "Utils.h"

FileLogger::FileLogger(const char* fileName) {
	std::string name = fileName;

	time_t t = time(NULL);
	struct tm* tmp = localtime(&t);
	char ts[200];
	strftime(ts, 200, ".%y%m%d-%H%M", tmp);
	name += ts + std::string(".log");

	errno_t ret = fopen_s(&ptr, name.c_str(), "wb+");
	if (ret==0) {
		log("Logger started");
	}
}

FileLogger::~FileLogger() {
	if(ptr) fclose(ptr);
}

std::string FileLogger::getCurrentTimeString() {
	time_t t = time(NULL);
	struct tm tmp;
	
	errno_t ret = localtime_s(&tmp, &t);
	if (ret != 0) return "";
	char ts[201] = { 0 };
	strftime(ts, 200, "%Y-%m-%d %H:%M:%S", &tmp);
	return  ts;
}


void FileLogger::log(const std::string& msg) {
	if (!ptr) return;

	std::string txt = getCurrentTimeString() + " " + msg + "\n";
	fwrite(txt.c_str(), 1, txt.size(), ptr);
	fflush(ptr);

	printf("%s", txt.c_str());
}

void FileLogger::log2(const std::string& msg, int value) {
	if (!ptr) return;

	std::string hex = "0x" + Utils::intToHexString(value);
	std::string txt = getCurrentTimeString() + " " + msg + std::string(" ") + std::to_string(value) + " " +hex + std::string("\n");
	fwrite(txt.c_str(), 1, txt.size(), ptr);
	fflush(ptr);

	printf("%s", txt.c_str());
}

void FileLogger::log3(const std::string& msg, int value1, int value2) {
	if (!ptr) return;

	std::string hex1 = "0x" + Utils::intToHexString(value1);
	std::string hex2 = "0x" + Utils::intToHexString(value2);

	std::string txt = getCurrentTimeString() + " " + msg + std::string(" ") + std::to_string(value1) +"["+ hex1 +"] " + std::to_string(value2) + " ["+ hex2+std::string("]\n");
	fwrite(txt.c_str(), 1, txt.size(), ptr);
	fflush(ptr);

	printf("%s", txt.c_str());
}
