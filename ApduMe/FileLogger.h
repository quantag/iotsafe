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

