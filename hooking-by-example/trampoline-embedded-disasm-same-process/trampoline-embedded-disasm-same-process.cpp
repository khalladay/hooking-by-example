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

extern "C" void call_hook_payload();



void InstallHook(HookDesc* hook)
{
	DWORD oldProtect;
	bool err = VirtualProtect(hook->originalFunc, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	// Disassemble stolen bytes
	csh handle;
	cs_err dis_err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	check(dis_err == CS_ERR_OK);

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

	//build stolen bytes
	uint8_t* stolenBytes = (uint8_t*)malloc(hook->stolenInstructionSize);
	uint8_t* stolenByteIter = stolenBytes;
	for (int i = 0; i < hook->stolenInstructionCount; ++i)
	{
		memcpy(stolenByteIter, hook->stolenInstructions[i].bytes, hook->stolenInstructions[i].size);
		stolenByteIter += hook->stolenInstructions[i].size;
	}

	uint8_t callAsmBytes[] = {	0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //movabs 64 bit value into rax
								0xFF, 0xD0, //call rax
							};

	memcpy(&callAsmBytes[2], &hook->payloadFunc, sizeof(uint64_t));
	//write trampoline func
	uint64_t addrOfCallHookPayload = (uint64_t)call_hook_payload;
	err = VirtualProtect(call_hook_payload, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);
	uint8_t* payloadPtr = (uint8_t*)call_hook_payload;
	memcpy(&payloadPtr[33], &callAsmBytes, sizeof(callAsmBytes));

	memcpy(&callAsmBytes[2], &addrOfCallHookPayload, sizeof(uint64_t));

	uint8_t jmpBytes[] = { 0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //movabs into rax
							0xFF, 0xE0 }; //jmp rax

	uint64_t orignFuncPostJmp = uint64_t(hook->originalFunc) + 5;
	memcpy(&jmpBytes[2], &orignFuncPostJmp, sizeof(void*));

	uint8_t* trampolineBytePtr = (uint8_t*)hook->trampolineMem;

	uint64_t hookPayloadAddr = (uint64_t)call_hook_payload;
	memcpy(trampolineBytePtr, &callAsmBytes, sizeof(callAsmBytes));
	trampolineBytePtr += sizeof(callAsmBytes);
	memcpy(trampolineBytePtr, stolenBytes, hook->stolenInstructionSize);
	trampolineBytePtr += hook->stolenInstructionSize;
	memcpy(trampolineBytePtr, jmpBytes, sizeof(jmpBytes));
	free(stolenBytes);

	//write jumps
	WriteAbsoluteJump64(hook->longJumpMem, hook->trampolineMem);
	WriteRelativeJump(hook->originalFunc, hook->longJumpMem, hook->stolenInstructionSize - 5);

}

int main(int argc, const char** argv)
{	
	float y = atof(argv[0]);
	TargetFunc(argc, (float)argc);
	HookDesc hook = { 0 };
	hook.originalFunc = TargetFunc;
	hook.payloadFunc = HookPayload;
	hook.longJumpMem = AllocatePageNearAddress(TargetFunc);
	hook.trampolineMem = AllocPage();

	InstallHook(&hook);

	TargetFunc(argc-1, (float)argc);

}

