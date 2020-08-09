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

//while calling conventions differ between x86 and x64, both
//pass the "this" pointer in rcx
uint8_t hookPayloadFuncBytes[] = {
	0x48, 0x8B, 0x01,		// mov rax, [rcx]
	0x48, 0x83, 0xC0, 0x64, // add rax, 64h
	0xC3
};

int main(int argc, const char** argv)
{
	check(argc == 2);
	bool err;

	//the process we're hooking does NOT have debug symbols, so instead of looking
	//up the function we want to hook by symbol name, we need to find the relative
	//virtual address (RVA) of that function in something like x64dbg, and pass it to
	//this program
	uint64_t inputRVA = _strtoui64(argv[1], nullptr, 16);

	DWORD processID = FindPidByName("target-with-nonvirtual-member-functions.exe");
	check(processID);

	HANDLE remoteProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	check(remoteProcessHandle);

	HMODULE base = GetBaseModuleForProcess(remoteProcessHandle);
	check(base);

	void* func2hook = (void*)((addr_t)base + (addr_t)inputRVA);

	void* payloadAddrInRemoteProcess = AllocPageInTargetProcess(remoteProcessHandle);
	check(payloadAddrInRemoteProcess);
	err = WriteProcessMemory(remoteProcessHandle, payloadAddrInRemoteProcess, hookPayloadFuncBytes, sizeof(hookPayloadFuncBytes), nullptr);
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