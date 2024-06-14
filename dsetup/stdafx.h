#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <stdio.h>
#include <winsock2.h>
#include <process.h>
#include <intrin.h>
#include <iphlpapi.h>
#include "WinIoCtl.h"
#include <fstream>
#include <iostream>
#include <string>

#define L2_API __declspec(dllimport)
#include "DirectX.h"

#include "ProtectThread.h"
#include "Hook.h"

#include "DiscordSDK.h"