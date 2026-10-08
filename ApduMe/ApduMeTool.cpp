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

// ApduMe: replays an APDU script against a PC/SC smart card reader.

#include <iostream>
#include "FileIO.h"
#include "DriverDirect.h"
#include "FileLogger.h"
#include "Utils.h"
#include "ApduFile.h"

/**
*   Main entry
*/
int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Specify input file to execute" << std::endl;
        return 1;
    }

    FileLogger logger(argv[1]);
    logger.log("ApduMe v1.0.0 started");

    std::string inputFile = argv[1];
  
    TestFile in;
    in.logger = &logger;
    int ret = in.loadCstyle(inputFile);
    ASSERTIT(ret);
    logger.log2("Loaded input APDU commands ", (int)in.lines.size());
 //   in.testLines();

    DriverDirect driver;
    driver.setLogger(&logger);

    std::map<std::string, std::string> config;
    bool ok = Utils::loadIniFile(L"apdume.ini", config);
    if (ok) {
        // loaded .ini file
        logger.log("ini file loaded");
        driver.applyConfig(config);
    }

    int okTests = 0;
    int failedTests = 0;
    for (size_t i = 0; i < in.lines.size(); i++) {
        std::string inputData = in.lines.at(i);

        std::string binInputData = Utils::getBinApdu(inputData);
        if (binInputData.empty()) continue;
        std::string response;
        logger.log(">>> (" + Utils::IntToString( (int)binInputData.size()) + " bytes) :" +  Utils::bin2hex(binInputData, true) );

        ret = driver.transmit(Utils::hex2bin(inputData), response);
        ASSERTIT(ret);

        std::string responseHex = Utils::bin2hex(response, true);
        logger.log("<<< (" + Utils::IntToString( (int)response.size()) + " bytes) :" + responseHex);
    }
 
    return 0;
}

