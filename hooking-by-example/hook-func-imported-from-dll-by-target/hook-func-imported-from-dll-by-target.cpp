/*	Hooking-By-RVA

	This program shows how to install a hook in a running process
	that has been built without debug symbols. The hook that
	gets installed is "destructive" in the sense that it doesn't use
	a trampoline, so the original version of the hooked function is
	completely destroyed.

	For this example, we're hooking a member function of an object
	in the target process, and our payload instructions will use
	a private data member of that object, so we have to pay attention
	to what calling convention is being used (to access the "this"
	pointer).
*/

#include "..\hooking_common.h"

#define TARGET_APP_NAME "target-with-functions-from-dll.exe"
#define DLL_NAME "getnum-dll.dll"
#define FUNC2HOOK_NAME "getNum"

const uint8_t hookPayload[] =
{
	0xB8, 0x64, 0x0, 0x0, 0x0, // mov eax, 64h
	0xC3					   // ret
};

//hacky way to get the path to the correct dll for
//whatever the active build config is... saves having to 
//provide the path on the command line, but is otherwise
//not particularly important
void GetPathToDLL(char* outPath, size_t outPathSize)
{
	char relPath[1024];
	char thisAppName[1024];
	GetModuleFileName(NULL, relPath, 1024);
	GetModuleBaseName(GetCurrentProcess(), NULL, thisAppName, 1024);
	char* replaceStart = strstr(relPath, thisAppName);
	const char* dllName = DLL_NAME;
	memcpy(replaceStart, dllName, strlen(dllName));
	memset(replaceStart + strlen(dllName), '\0', &relPath[1024] - (replaceStart + strlen(dllName)));

	_fullpath(outPath, relPath, outPathSize);
}


int main(int argc, const char** argv)
{
	bool err;

	DWORD processID = FindPidByName(TARGET_APP_NAME);
	check(processID);

	HANDLE remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(remoteProcessHandle);

	HMODULE base = GetBaseModuleForProcess(remoteProcessHandle);
	check(base);

	char dllPath[1024];
	GetPathToDLL(dllPath, 1024);

	void* func2hook = FindAddressOfRemoteDLLFunction(remoteProcessHandle, dllPath, FUNC2HOOK_NAME);

	void* payloadAddrInRemoteProcess = AllocPageInTargetProcess(remoteProcessHandle);
	check(payloadAddrInRemoteProcess);
	err = WriteProcessMemory(remoteProcessHandle, payloadAddrInRemoteProcess, hookPayload, sizeof(hookPayload), nullptr);
	check(err);

	void* hookJumpTarget = payloadAddrInRemoteProcess;

	//it's possible for functions to be located farther than a 32 bit jump away from one
	//another in a 64 bit program, (but there's no 64 bit relative jump instruction), so
	//if the victim process is 64 bit, we need to write an absolute jump instruction somewhere
	//close to func2hook. The E9 jump that gets installed in func2hook will jump to these
	//instructions, which will then do a 64 bit absolute jump to the payload.
	if (IsProcess64Bit(remoteProcessHandle))
	{
		void* absoluteJumpMemory = AllocatePageNearAddressRemote(remoteProcessHandle, func2hook);
		check(absoluteJumpMemory != nullptr);
		WriteAbsoluteJump64(remoteProcessHandle, absoluteJumpMemory, payloadAddrInRemoteProcess);
		hookJumpTarget = absoluteJumpMemory;
	}

	//finally, write the actual "hook" into the target function. On 32 bit
	//this will jump directly to the payload, on 64 bit, it jumps to the 
	//absolute jump that we made above, which jumps to the payload
	WriteRelativeJump(remoteProcessHandle, func2hook, hookJumpTarget);
	return 0;
}