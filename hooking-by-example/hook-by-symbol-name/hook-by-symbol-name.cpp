/*	Hook-By-Symbol-Name
	
	This program shows how to install a hook in a running process
	that has been built with debug symbols enabled. The hook that
	gets installed is "destructive" in the sense that it doesn't use
	a trampoline, so the original version of the hooked function is 
	completely destroyed. 

	In this case, that doesn't matter, because the original function
	just returns a constant (0), and the hook payload that gets installed
	replaces that with a diffferent constant (100). The payload in this 
	example program is so simple that it can almost entirely ignore calling
	conventions, since it doesn't use function args, and only pollutes raxs
*/

#include "..\hooking_common.h"

#include <DbgHelp.h>
#pragma comment (lib, "Dbghelp.lib")

const uint8_t hookPayload[] =
{
	0xB8, 0x64, 0x0, 0x0, 0x0, // mov eax, 64h
	0xC3					   // ret
};

int main(int argc, const char** argv)
{
	bool err; 

	DWORD processID = FindPidByName("target-with-free-functions.exe");
	check(processID);

	HANDLE remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(remoteProcessHandle);

	//this process' pointer size needs to match the target process
	check(IsProcess64Bit(remoteProcessHandle) == IsProcess64Bit(GetCurrentProcess));

	//the target program that this program hooks (target-with-free-functions.exe)
	//has been built with debug symbols enabled, which means we can get the address
	//of the function to hook by looking up it's name in the symbol table
	err = SymInitialize(remoteProcessHandle, NULL, true);
	check(err);
	SYMBOL_INFO symInfo = { 0 };
	symInfo.SizeOfStruct = sizeof(symInfo);
	err = SymFromName(remoteProcessHandle, "getNum", &symInfo);
	check(err);

	void* func2hook = (void*)symInfo.Address;

	//next step is to write the payload function to the victim process' memory
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
