#include <stdio.h>
#include <cstdlib>
#include "capstone/x86.h"
#include "../hooking_common.h"
#include "capstone/capstone.h"
#include <vector>

void HookPayload()
{
	printf("Hook executed\n");
}

__declspec(noinline) void TargetFunc(int x, float y)
{
	switch (x) 
	{
		case 0: printf("0 args %f\n", y); break;
		case 1: printf("1 args\n"); break;
		default:printf(">1 args\n"); break;
	}
}


struct HookDesc
{
	void* originalFunc;
	void* payloadFunc;
	void* trampolineMem;
	void* longJumpMem;

	cs_insn* stolenInstructions;
	uint8_t stolenInstructionCount;
	uint8_t stolenInstructionSize;
};

void InstallHook(HookDesc* hook)
{
	DWORD oldProtect;
	bool err = VirtualProtect(hook->originalFunc, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	// Disassemble stolen bytes
	csh handle;
	cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	check(err == CS_ERR_OK);

	size_t count;
	count = cs_disasm(handle, (uint8_t*)hook->originalFunc, 20, (uint64_t)hook->originalFunc, 20, &hook->stolenInstructions);
	check(count > 0);

	for (int i = 0; i < count; ++i)
	{
		cs_insn inst = hook->stolenInstructions[i];
		hook->stolenInstructionSize += inst.size;
		hook->stolenInstructionCount++;
		if (hook->stolenInstructionSize >= 5) break;
	}
	check(hook->stolenInstructionSize >= 5);
	cs_close(&handle);

	WriteRelativeJump(hook->originalFunc, hook->longJumpMem, hook->stolenInstructionSize - 5);
}

int main(int argc, const char** argv)
{	
	HookDesc hook;
	hook.originalFunc = TargetFunc;
	hook.payloadFunc = HookPayload;
	hook.longJumpMem = AllocatePageNearAddress(TargetFunc);
	hook.trampolineMem = AllocPage();

	InstallHook(&hook);

	float y = atof(argv[0]);
	TargetFunc(argc, (float)argc);

	//build trampoline data structure

		/* trampoline layout

	push args onto stack
	alloc shadow space
	call payload
	pop args back into registers
	stolen bytes

	***jump table***
	push rax, ABS ADDR
	jmp rax
	push rax, ABS ADDR
	jmp rax
	etc

	*/
}

