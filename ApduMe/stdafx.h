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

// stdafx.h : shared declarations and the Windows headers this tool needs.
//
// ApduMe is a console program. It previously pulled in MFC (afxwin.h,
// afxext.h, afxdtctl.h, afxcmn.h) for a single string class, which made the
// build depend on the Visual Studio MFC component and meant the tool could
// not be built with the C++ workload alone. MFC has been removed: the string
// handling now uses std::wstring, and only the Win32 headers remain.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN     // exclude rarely-used parts of the Windows headers
#endif

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif

// Minimum supported platform: Windows 7.
#ifndef WINVER
#define WINVER 0x0601
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif						

#include <windows.h>
#include <tchar.h>      // _tcslen and friends; MFC used to pull this in

enum ErrCode {
	eOk = 0,
	eFatal = 1,
	eBadFile = 2,
	eBadIniFile = 3
};

typedef unsigned char  byte;