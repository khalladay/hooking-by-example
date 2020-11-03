#include "trampoline-imported-func-payload.h"
#include <stdio.h>
#include <stack>
#include <vector>
#include "capstone/x86.h"
#include "../hooking_common.h"
#include "../trampoline_common.h"
#include "capstone/capstone.h"

#define TARGET_APP_NAME "B - Target With Free Function From DLL.exe"
#define TARGET_DLL_NAME "B2 - GetNum-DLL.dll"
#define FUNC2HOOK_NAME "GetNum"

/**************************
 * HOOKING CODE           *
 **************************/
thread_local std::stack<uint64_t> hookJumpAddresses;
void PushAddress(uint64_t addr) //push the address of the jump target
{
	hookJumpAddresses.push(addr);
}

//we absolutely don't want this inlined
__declspec(noinline) void PopAddress(uint64_t trampolinePtr)
{
	uint64_t addr = hookJumpAddresses.top();
	hookJumpAddresses.pop();
	memcpy((void*)trampolinePtr, &addr, sizeof(uint64_t));
}

void InstallHook(void* func2hook, void* payloadFunc)
{
	SetOtherThreadsSuspended(true);

	DWORD oldProtect;
	VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

	//102 is the size of the "pre-payload" instructions that are written below
	//the trampoline will be located after these instructions in memory
	void* hookMemory = AllocatePageNearAddress(func2hook);

	uint32_t trampolineSize = BuildTrampoline(func2hook, (void*)((char*)hookMemory + 102));

	uint8_t* memoryIter = (uint8_t*)hookMemory;
	uint64_t trampolineAddress = (uint64_t)(memoryIter)+102;

	memoryIter += WriteSaveArgumentRegisters(memoryIter);
	memoryIter += WriteMovToRCX(memoryIter, trampolineAddress);
	memoryIter += WriteSubRSP32(memoryIter); //allocate home space for function call
	memoryIter += WriteAbsoluteCall64(memoryIter, &PushAddress);
	memoryIter += WriteAddRSP32(memoryIter);
	memoryIter += WriteRestoreArgumentRegisters(memoryIter);
	memoryIter += WriteAbsoluteJump64(memoryIter, payloadFunc);

	//create the relay function
	void* relayFuncMemory = memoryIter + trampolineSize;
	WriteAbsoluteJump64(relayFuncMemory, hookMemory); //write relay func instructions

	//install the hook
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
	const int32_t relAddr = int32_t((int64_t)relayFuncMemory - ((int64_t)func2hook + sizeof(jmpInstruction)));
	memcpy(jmpInstruction + 1, &relAddr, 4);
	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));

	SetOtherThreadsSuspended(false);
}

/**************************
 * PAYLOAD CODE           *
 **************************/

int(*target)();// = nullptr;
int GetNumPayload()
{
	//this payload is used with the demo program "trampoline-imported-func-with-dll-injection
	//and is meant to be injected into the target app "target-with-functions-from-dll"
	//this payload hooks the "getNum" function found in the "getnum-dll" project
	printf("Trampoline Executed\n");

	PopAddress(uint64_t(&target));
	return target();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD ul_reason_for_call, LPVOID lpvReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		printf("Function Payload Injected Successfully \n");
		HMODULE mod = FindModuleInProcess(GetCurrentProcess(), TARGET_DLL_NAME);

		void* localHookFunc = GetProcAddress(mod, FUNC2HOOK_NAME);
		InstallHook(localHookFunc, GetNumPayload);
	}
	return true;
}