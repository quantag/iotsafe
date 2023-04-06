#pragma once

#include <string>
#include <vector>

class FileLogger;

class TestFile
{
public:
	TestFile();
	virtual ~TestFile();

	int load(const std::string& name);
	int loadCstyle(const std::string& name);

	static bool isCommentLine(const std::string& line);
	static std::string removeCommentLines(const std::string& content);

	std::vector<std::string> lines;

	void testLines();
	FileLogger* logger;

};

