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

#include "ApduFile.h"

#include "FileIO.h"
#include "Utils.h"
#include "FileLogger.h"


TestFile::TestFile() : logger(nullptr){
}

TestFile::~TestFile() {
}

bool TestFile::isCommentLine(const std::string& _line) {
	std::string line = Utils::trim(_line);
	if (line.empty())
		return true;

	if (line.at(0) == '#') return true;

	if (line.size() > 2) {
		char ch = line.at(0);
		char ch1 = line.at(1);
		if (ch == '/' && ch1 == '/')
			return true;
	}

	if (line.at(0) == '\r') return true; // treat empty lines as comments
	if (line.at(0) == '\n') return true; // treat empty lines as comments

	return false;
}

/**
*  load text files by lines seoarated by \n
*/
int TestFile::load(const std::string& name) {
	std::string content0;
	int ret = FileIO::readFile(name, content0);
	ASSERTIT(ret);

	std::string content = removeCommentLines(content0);

	std::string delimiter = "\r";
	lines.clear();

	size_t pos = 0;
	std::string token;
	while ((pos = content.find(delimiter)) != std::string::npos) {
		token = content.substr(0, pos);
		lines.push_back(token);
		content.erase(0, pos + delimiter.length());
	}
	lines.push_back(content);

	return 0;
}

std::string TestFile::removeCommentLines(const std::string& _content) {
	std::string content = _content;
	size_t pos = 0;
	std::string token;
	std::string delimiter = "\n";
	std::string out = "";

	while ((pos = content.find(delimiter)) != std::string::npos) {
		token = content.substr(0, pos);
		if (!isCommentLine(token)) {	// skip comments line
			out += token;
		}
		content.erase(0, pos + delimiter.length());
	}

	if (!isCommentLine(content)) 	// skip comments line	
		out += content;

	return out;
}

/**
*  load text files by lines seoarated by ;
*/
int TestFile::loadCstyle(const std::string& name) {
	std::string content0;
	int ret = FileIO::readFile(name, content0);
	ASSERTIT(ret);

	std::string delimiter = ";";
	lines.clear();

	std::string content1 = removeCommentLines(content0);
	std::string content2 = Utils::removeChar(content1, '\r');
	std::string content = Utils::removeChar(content2, ' ');

	size_t pos = 0;
	std::string token;

	std::string tmpLine = "";
	while ((pos = content.find(delimiter)) != std::string::npos) {
		token = content.substr(0, pos);
		if (!isCommentLine(token)) {	// skip comments line
			lines.push_back(token);
		}
		content.erase(0, pos + delimiter.length());
	}

	if (!isCommentLine(content)) 	// skip comments line	
		lines.push_back(content);

	return 0;
}

void TestFile::testLines() {
	for (int i = 0; i < lines.size(); i++) {
		std::string line = lines.at(i);
		std::string hex = Utils::apduToolLineToHex(line);
		if (hex.empty()) continue;
		LOG(hex);
	}
}
