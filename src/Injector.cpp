
#include "linject.h"
#include <Psapi.h>
#include <tchar.h>

// Bootil Library
using namespace Bootil;

const DWORD MAXINJECTSIZE = 4096;
typedef HMODULE(__stdcall *PGetModuleHandleA)(char*);
typedef HMODULE(__stdcall *PLoadLibrary)(char*);
typedef BOOL(__stdcall *PFreeLibrary)(HMODULE);
typedef FARPROC(__stdcall *PGetProcAddress)(HMODULE, char*);

// Payload struct, contains metadata we use within target process context
struct RemoteThreadBlock
{
	PGetModuleHandleA	fnGetModuleHandle;			// FunctionPointer for GetModuleHandle() which we retrieve BEFORE injecting
	PFreeLibrary		fnFreeLibrary;				// FunctionPointer for FreeLibrary (for ejecting)
	PLoadLibrary		fnLoadLibrary;				// FunctionPointer for LoadLibrary (for injecting)
	PGetProcAddress		fnGetProcAddress;			// FunctionPointer for GetProcAddress
	bool				bTrueForInject;				// 1=inject, 0=eject. should we inject or eject?
	DWORD				ErrorFree;					// return success

	char				lpModulePath[512];			// name and path of DLL to be injected or ejected
	HMODULE				hModule;					// ModuleHandle for ejecting
};

// Function which we will insert 
DWORD __stdcall RemoteThread(RemoteThreadBlock*);

// Internal, do not call externally
int InjectOrEject(DWORD PID, LPSTR chDllName, BOOL bMode = 0);

// Payload Function
DWORD __stdcall RemoteThread(RemoteThreadBlock* execBlock)
{
	if (execBlock->bTrueForInject == false)
	{
		execBlock->hModule = (*execBlock->fnGetModuleHandle)(execBlock->lpModulePath);
		execBlock->ErrorFree = execBlock->fnFreeLibrary(execBlock->hModule);
	}
	else
	{
		execBlock->hModule = (*execBlock->fnLoadLibrary)(execBlock->lpModulePath);
		execBlock->ErrorFree = execBlock->hModule != NULL ? 0 : 1;
	}

	return 0;
}


// Insert remoteThread Payload & remoteThreadBlock struct with WriteProcessMemory
int InjectOrEject(DWORD PID, BString dllName, BOOL bTrueForInject)
{
	int nResult = 0;		// phaseFlag. If <>0 skip rest phases and bailout
	HANDLE hProcess = NULL;
	HANDLE ht = NULL;
	RemoteThreadBlock localCopy;
	RemoteThreadBlock *c = 0;
	void *p = 0;
	DWORD rc = 0;

	LPSTR chDllName = (char*)dllName.c_str();

	// Validate PID
	if (PID <= 0) {
		return 1;
	}

	// clear the parameter block
	::ZeroMemory(&localCopy, sizeof(localCopy));

	// Open the process and bailout if not success
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, PID);

	if (!hProcess)
	{ 
		nResult = 1; 
	}

	// allocate memory in the remote process for injected function (code)
	if (nResult) goto cleanup; // Bailout if previous phase did not succeed
	
	p = VirtualAllocEx(hProcess, 0, MAXINJECTSIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	if (p)
	{
		// If memoryallocation succeed write the RemoteThread()-function to target process
		if (!WriteProcessMemory(hProcess, p, &RemoteThread, MAXINJECTSIZE, 0))
		{
			nResult = 3;
		}
	} else {
		nResult = 2;
	}

	// Allocate space in the remote process for the parameterblock and poke it in
	if (nResult) goto cleanup;

	c = (RemoteThreadBlock*)VirtualAllocEx(hProcess, NULL, sizeof(RemoteThreadBlock), MEM_COMMIT, PAGE_READWRITE);
	
	if (c) 
	{
		// Build the functionpointers and store them to RemoteThreadBlock
		strcpy(localCopy.lpModulePath, chDllName);

		localCopy.fnGetModuleHandle = (PGetModuleHandleA)GetProcAddress(GetModuleHandle("Kernel32"), "GetModuleHandleA");
		localCopy.fnFreeLibrary = (PFreeLibrary)GetProcAddress(GetModuleHandle("Kernel32"), "FreeLibrary");
		localCopy.fnLoadLibrary = (PLoadLibrary)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");
		localCopy.fnGetProcAddress = (PGetProcAddress)GetProcAddress(GetModuleHandle("Kernel32"), "GetProcAddress");
		localCopy.bTrueForInject = bTrueForInject;

		// copy the parameterblock to the other process adressspace
		if (!WriteProcessMemory(hProcess, c, &localCopy, sizeof localCopy, 0))
		{
			nResult = 5;
		}
	} else {
		nResult = 4;
	}

	// Now we are ready to start the actual RemoteThread and pass pointer function that we poked in AND to paramter-block we also poked.
	if (nResult) goto cleanup;
	
	ht = CreateRemoteThread(hProcess, 0, 0, (DWORD(__stdcall *)(void *)) p, c, 0, &rc); // p=pointer to our function, c=pointer to our parameter-block
	
	if (ht == NULL) 
	{
		nResult = 6;
	}

	if (nResult) goto cleanup;

	// Wait max 5000ms for remotethread to be executed (DLL loaded or unloaded) 
	rc = WaitForSingleObject(ht, 2500);

	if (rc == WAIT_OBJECT_0)
	{
		// Read the parameter-block back from remote-process. Then we can check errorFree-return value.
		ReadProcessMemory(hProcess, c, &localCopy, sizeof localCopy, 0);
	} else {
		nResult = 7;
	}

	if ((int)localCopy.ErrorFree)
	{
		nResult = 0; // success
	} else {
		nResult = 8;
	}

cleanup:
	// Free reserved memory from target process
	if (p != 0)	
	{
		VirtualFreeEx(hProcess, p, 0, MEM_RELEASE);
	}

	if (c != 0)
	{
		VirtualFreeEx(hProcess, c, 0, MEM_RELEASE);
	}

	if (ht)
	{
		CloseHandle(ht);
	}

	if (hProcess)
	{
		CloseHandle(hProcess);
	}

	return nResult;
}

int Injector::Inject(DWORD PID, BString dllName)
{
	return InjectOrEject(PID, dllName, true);
}

int Injector::Eject(DWORD PID, BString dllName)
{
	return InjectOrEject(PID, dllName, false);
}

bool Injector::IsModuleLoaded(DWORD PID, BString dllName)
{
	String::Lower(dllName);

	LPSTR strModuleName = (char*)dllName.c_str();

	MODULEENTRY32 lpme = { 0 };
	int nModules = 0;
	BOOL isMod = 0;
	BOOL isFound = false;
	char strModName[512];

	strcpy(strModName, strModuleName);

	HANDLE hSnapshotModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hSnapshotModule)
	{
		lpme.dwSize = sizeof(lpme);
		isMod = Module32First(hSnapshotModule, &lpme);

		while (isMod)
		{
			if (strcmp(_strlwr(lpme.szExePath), strModName) == 0)
			{
				isFound = true;
			}
			nModules++;
			isMod = Module32Next(hSnapshotModule, &lpme);
		}
	}

	CloseHandle(hSnapshotModule);

	if (isFound)
	{
		return true;
	}

	return false;
}

DWORD Injector::GetProcess(BString procName)
{
	LPSTR szExeName = (char*)procName.c_str();

	DWORD dwRet = 0;
	DWORD dwCount = 0;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe = { 0 };
		pe.dwSize = sizeof(PROCESSENTRY32);

		BOOL bRet = Process32First(hSnapshot, &pe);

		while (bRet)
		{
			if (!_stricmp(pe.szExeFile, szExeName))
			{
				dwCount++;
				dwRet = pe.th32ProcessID;
			}
			bRet = Process32Next(hSnapshot, &pe);
		}

		if (dwCount > 1)
			dwRet = 0xFFFFFFFF;

		CloseHandle(hSnapshot);
	}

	return dwRet;
}

int Injector::StartInject(BString procName, BString dllName)
{
	DWORD PID = Injector::GetProcess(procName);

	if (PID == 0)
	{
		Output::Warning("Could not find process %s\n", procName.c_str());

		return 0;
	}

	char RealPath[MAX_PATH] = { 0 };
	GetFullPathName(dllName.c_str(), MAX_PATH, RealPath, NULL);

	BString FixedPath = String::Format::Print(RealPath);
	BString NiceDllName = dllName;

	String::File::ExtractFilename(NiceDllName);

	if (Injector::IsModuleLoaded(PID, FixedPath))
	{
		Output::Warning("%s already has %s loaded\n", procName.c_str(), NiceDllName.c_str());

		return 0;
	}

	Injector::Inject(PID, FixedPath);

	bool result = Injector::IsModuleLoaded(PID, FixedPath);

	if (result)
	{
		DWORD* baseAddress = Injector::GetBaseAddress(PID, FixedPath);

		Console::FGColorPush(Console::Green);
		Output::Msg("%s successfully injected into %s [PID %d] (0x%0x)\n", NiceDllName.c_str(), procName.c_str(), PID, baseAddress);
		Console::FGColorPop();
	} else {
		Output::Warning("%s failed to inject into %s [PID %d]\n", NiceDllName.c_str(), procName.c_str(), PID);
	}

	return result;
}

int Injector::StartEject(BString procName, BString dllName)
{
	DWORD PID = Injector::GetProcess(procName);

	if (PID == 0)
	{
		Output::Warning("Could not find process %s\n", procName.c_str());

		return 0;
	}

	char RealPath[MAX_PATH] = { 0 };
	GetFullPathName(dllName.c_str(), MAX_PATH, RealPath, NULL);

	BString FixedPath = String::Format::Print(RealPath);
	BString NiceDllName = dllName;

	String::File::ExtractFilename(NiceDllName);

	if (!Injector::IsModuleLoaded(PID, FixedPath))
	{
		Output::Warning("%s does not have %s loaded\n", procName.c_str(), NiceDllName.c_str());

		return 0;
	}

	Injector::Eject(PID, FixedPath);

	bool result = Injector::IsModuleLoaded(PID, FixedPath);

	if (!result)
	{
		Console::FGColorPush(Console::Green);
		Output::Msg("successfully ejected %s from %s [PID %d]\n", NiceDllName.c_str(), procName.c_str(), PID);
		Console::FGColorPop();
	}
	else {
		Output::Warning("failed to eject %s from %s [PID %d]\n", NiceDllName.c_str(), procName.c_str(), PID);
	}

	return result;
}

int Injector::DumpModules(DWORD PID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, PID);
	if (NULL == hProcess)
		return 1;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				Output::Msg("\t%s (0x%08X)\n", szModName, hMods[i]);
			}
		}
	}

	CloseHandle(hProcess);

	return 0;
}

int Injector::StartProcess(BString procPath, BString dllName, DWORD delay)
{
	char RealPath[MAX_PATH] = { 0 };
	GetFullPathName(dllName.c_str(), MAX_PATH, RealPath, NULL);

	BString FixedPath = String::Format::Print(RealPath);

	BString NiceDllName = dllName;
	BString NiceProcName = procPath;

	String::File::ExtractFilename(NiceDllName);
	String::File::ExtractFilename(NiceProcName);

	STARTUPINFOA startInfo;
	PROCESS_INFORMATION procInfo;

	ZeroMemory(&startInfo, sizeof(startInfo));
	ZeroMemory(&procInfo, sizeof(procInfo));

	startInfo.cb = sizeof(startInfo);

	Output::Msg("starting %s\n", NiceProcName.c_str());

	HANDLE hProcess = Process::Start(procPath, "", true);

	if (hProcess == NULL)
	{
		Output::Warning("Failed to start process %s\n", NiceProcName.c_str());

		return 0;
	}

	Output::Msg("%s started successfully\n", NiceProcName.c_str());

	DWORD PID = Injector::GetProcess(NiceProcName);

	if (PID == 0)
	{
		Output::Warning("Could not find PID of process %s\n", NiceProcName.c_str());

		return 0;
	}

	DWORD NiceDelay = ((delay + 500) / 1000); // Miliseconds to seconds

	Output::Msg("waiting %d seconds to inject into %s\n", NiceDelay, NiceProcName.c_str());

	Sleep(delay); // Sleep for 5 seconds

	Injector::Inject(PID, FixedPath);

	bool result = Injector::IsModuleLoaded(PID, FixedPath);

	if (result)
	{
		DWORD* baseAddress = Injector::GetBaseAddress(PID, FixedPath);

		Console::FGColorPush(Console::Green);
		Output::Msg("%s successfully injected into %s [PID %d] (0x%0x)\n", NiceDllName.c_str(), NiceProcName.c_str(), PID, baseAddress);
		Console::FGColorPop();
	}
	else {
		Output::Warning("%s failed to inject into %s [PID %d]\n", NiceDllName.c_str(), NiceProcName.c_str(), PID);
	}

	return result;
}

DWORD* Injector::GetBaseAddress(DWORD PID, BString dllName)
{
	String::Lower(dllName);

	LPSTR strModuleName = (char*)dllName.c_str();

	MODULEENTRY32 lpme = { 0 };
	int nModules = 0;
	BOOL isMod = 0;
	DWORD* baseAddress = 0;
	char strModName[512];

	strcpy(strModName, strModuleName);

	HANDLE hSnapshotModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hSnapshotModule)
	{
		lpme.dwSize = sizeof(lpme);
		isMod = Module32First(hSnapshotModule, &lpme);

		while (isMod)
		{
			if (strcmp(_strlwr(lpme.szExePath), strModName) == 0)
			{
				baseAddress = reinterpret_cast<DWORD*>(lpme.modBaseAddr);
			}
			nModules++;
			isMod = Module32Next(hSnapshotModule, &lpme);
		}
	}

	CloseHandle(hSnapshotModule);

	return baseAddress;
}
