#pragma once

#define WIN32_LEAN_AND_MEAN
#include "Bootil/Bootil.h"
#include <windows.h>
#include <Tlhelp32.h>

// Bootil Library
using namespace Bootil;

namespace Injector
{
	// Inject DLL
	int Inject(DWORD PID, BString dllName);

	// Eject DLL
	int Eject(DWORD PID, BString dllName);

	// Verify if DLL is loaded
	bool IsModuleLoaded(DWORD PID, BString dllName);

	// Get ProcessID by process name
	DWORD GetProcess(BString procName);

	// Start Injection Process
	int StartInject(BString procName, BString dllName);

	// Start Ejection Process
	int StartEject(BString procName, BString dllName);

	// Dump all DLLs in use by a target process
	int DumpModules(DWORD PID);

	// Get a Modules BaseAddress
	DWORD* GetBaseAddress(DWORD PID, BString dllName);
}
