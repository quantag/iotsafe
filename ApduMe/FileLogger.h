#pragma once

#include "stdafx.h"

#include <string>

#define LOG logger->log
#define LOG2 logger->log2
#define LOG3 logger->log3

class FileLogger {
public:
	FileLogger(const char* fileName);
	virtual ~FileLogger();

	void log(const std::string& msg);
	void log2(const std::string& msg, int value);
	void log3(const std::string& msg, int value1, int value2);

private:
	FILE* ptr;
	static std::string getCurrentTimeString();
};

