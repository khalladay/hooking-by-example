/*	Hooking-By-RVA-With-DLL-Payload

	This program shows how to install a hook in a running process
	that has been built without debug symbols. The hook that
	gets installed is "destructive" in the sense that it doesn't use
	a trampoline, so the original version of the hooked function is
	completely destroyed.

	In this example, the "payload" (or: where our hook redirects program
	flow to) is a function in a dll that is injected into the victim
	process. 

*/
#include "..\hooking_common.h"
#include <stdlib.h>

#define TARGET_APP_NAME "target-with-virtual-member-functions.exe"
#define PAYLOAD_DLL_NAME "payload-dll.dll"
#define PAYLOAD_FUNC_NAME "getNum"

void InjectPayload(HANDLE process, const char* pathToPayloadDLL)
{
	//write the name of our dll to the target process' memory
	size_t dllPathLen = strlen(pathToPayloadDLL);
	void* dllPathRemote = VirtualAllocEx(
		process,
		NULL, //let the system decide where to allocate the memory
		dllPathLen,
		MEM_COMMIT, //actually commit the virtual memory
		PAGE_READWRITE); //mem access for committed page

	check(dllPathRemote);

	BOOL writeSucceeded = WriteProcessMemory(
		process,
		dllPathRemote,
		pathToPayloadDLL,
		dllPathLen,
		NULL);

	check(writeSucceeded);

	PTHREAD_START_ROUTINE loadLibraryFunc = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32.dll")), "LoadLibraryA");
	check(loadLibraryFunc);

	//create a thread in remote process that loads our target dll using LoadLibraryA
	HANDLE remoteThread = CreateRemoteThread(
		process,
		NULL, //default thread security
		0, //stack size for thread
		loadLibraryFunc, //pointer to start of thread function (for us, LoadLibraryA)
		dllPathRemote, //pointer to variable being passed to thread function
		0, //0 means the thread runs immediately after creation
		NULL); //we don't care about getting back the thread identifier

	check(remoteThread);

	// Wait for the remote thread to terminate
	WaitForSingleObject(remoteThread, INFINITE);

	//once we're done, free the memory we allocated in the remote process for the dllPathname, and shut down
	VirtualFreeEx(process, dllPathRemote, 0, MEM_RELEASE);
	CloseHandle(remoteThread);
}

//hacky way to get the path to the correct payload for
//whatever the active build config is... saves having to 
//provide the path on the command line, but is otherwise
//not particularly important
void GetPathToPayloadDLL(char* outBuff)
{
	char relPath[1024];
	char thisAppName[1024];
	GetModuleFileName(NULL, relPath, 1024);
	GetModuleBaseName(GetCurrentProcess(), NULL, thisAppName, 1024);
	char* replaceStart = strstr(relPath, thisAppName);
	const char* payloadDLLName = PAYLOAD_DLL_NAME;
	memcpy(replaceStart, payloadDLLName, strlen(payloadDLLName));
	memset(replaceStart + strlen(payloadDLLName), '\0', &relPath[1024] - (replaceStart + strlen(payloadDLLName)));

	_fullpath(outBuff, relPath, 1024);
}

int main(int argc, const char** argv)
{
	check(argc == 2);

	//the process we're hooking does NOT have debug symbols, so instead of looking
	//up the function we want to hook by symbol name, we need to find the relative
	//virtual address (RVA) of that function in something like x64dbg, and pass it to
	//this program
	uint64_t inputRVA = _strtoui64(argv[1], nullptr, 16);

	DWORD processID = FindPidByName(TARGET_APP_NAME);
	check(processID);
	HANDLE remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(remoteProcessHandle);
	HMODULE base = GetBaseModuleForProcess(remoteProcessHandle);
	check(base);

	void* func2hook = (void*)((addr_t)base + (addr_t)inputRVA);

	//now that we have the address of the target function, we'll inject the payload
	//and write the relay function
	char fullPath[1024];
	GetPathToPayloadDLL(fullPath);
	HMODULE mod = FindModuleBaseAddress(remoteProcessHandle, fullPath);
	InjectPayload(remoteProcessHandle, fullPath);

	void* payloadAddrInRemoteProcess = FindAddressOfRemoteDLLFunction(remoteProcessHandle, fullPath, PAYLOAD_FUNC_NAME);
	check(payloadAddrInRemoteProcess);

	void* relayFunc = AllocatePageNearAddressRemote(remoteProcessHandle, func2hook);
	check(relayFunc != nullptr);
	WriteAbsoluteJump64(remoteProcessHandle, relayFunc, payloadAddrInRemoteProcess);

	//finally, write the actual "hook" into the target function. 
	WriteRelativeJump(remoteProcessHandle, func2hook, relayFunc);
	return 0;
}