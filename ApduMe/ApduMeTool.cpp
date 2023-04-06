// TestTool.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

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

