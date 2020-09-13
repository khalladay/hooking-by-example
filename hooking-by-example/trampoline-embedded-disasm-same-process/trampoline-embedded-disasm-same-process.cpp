#include <stdio.h>
#include <cstdlib>
#include "capstone/x86.h"
#include "../hooking_common.h"
#include "capstone/capstone.h"
#include <vector>


__declspec(noinline) void TargetFunc(int x, float y)
{
	switch (x) 
	{
		case 0: printf("0 args %f\n", y); break;
		case 1: printf("1 args\n"); break;
		default:printf(">1 args\n"); break;
	}
}

_declspec(noinline) void CallTargetFunc(int x, float y)
{
	if (x > 0) CallTargetFunc(x - 1, y);
	TargetFunc(x, y);
	printf("Target func called %i\n", x);
}


//this hardcoded gate function pointer could be replaced with something like a giant array of HookDescs that all contain gatePtrs
//and have the pre-hookpayload hook code set an ID for the currently active hook, then have the HookPayload func use that id to get the
//appropriate gate function pointer out of the global hook array. thread_local issues apply. 

void(*CallTargetGate)(int, float) = nullptr;
void HookPayload(int x, float y)
{
	//the static int check breaks if different functions or different threads all reroute to this payload
	//I think thread_local at least solves the thread problem
	thread_local static int r = 0;

	printf("Hook executed\n");
	if (r == 0)
	{
		r = 1;
		CallTargetGate(5, y);
	}
	else
	{
		CallTargetGate(x, y);
	}
	r = 0;
}


struct HookDesc
{
	void* originalFunc;
	void(**gatePtr)(int, float);
	void* payloadFunc;
	void* trampolineMem;
	void* longJumpMem;

	uint8_t stolenInstructionCount;
	uint8_t stolenInstructionSize;
};

extern "C" void call_hook_payload();

#pragma optimize("", off)

uint8_t WriteAbsoluteCallBytes(uint8_t* dst, void* funcToCall)
{
	uint8_t callAsmBytes[] = 
	{ 
		0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //movabs 64 bit value into rax
		0xFF, 0xD0, //call rax
	};
	memcpy(&callAsmBytes[2], &funcToCall, sizeof(void*));
	memcpy(dst, &callAsmBytes, sizeof(callAsmBytes));

	return sizeof(callAsmBytes);
}

uint8_t WriteAbsoluteJmpBytes(uint8_t* dst, void* addrToJumpTo)
{
	uint8_t jmpBytes[] =
	{
		0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //movabs into rax
		0xFF, 0xE0  //jmp rax
	};

	memcpy(&jmpBytes[2], &addrToJumpTo, sizeof(void*));
	memcpy(dst, &jmpBytes, sizeof(jmpBytes));

	return sizeof(jmpBytes);
}

//converts relative instructions to absolute ones
uint32_t BuildStolenByteBuffer(HookDesc* hook, uint8_t* outBuffer, uint8_t** outGapPtr, uint32_t outBufferSize)
{
	// Disassemble stolen bytes
	csh handle;
	cs_err dis_err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	check(dis_err == CS_ERR_OK);

	size_t count;
	cs_insn* disassembledInstructions;
	count = cs_disasm(handle, (uint8_t*)hook->originalFunc, 20, (uint64_t)hook->originalFunc, 20, &disassembledInstructions);
	check(count > 0);

	//get the instructions covered by the first 5 bytes of the original function
	uint32_t numBytes = 0;
	uint32_t numOriginBytes = 0;
	std::vector<std::pair<uint32_t, uint32_t>> jumps;
	std::vector<std::pair<uint32_t, uint32_t>> calls;
	uint32_t numInstructions = 0;

	for (int i = 0; i < count; ++i)
	{
		cs_insn inst = disassembledInstructions[i];
		//all condition jumps are relative, as are all E9 jmps. non-E9 "jmp" is absolute, so no need to deal with it
		bool isRelJump = inst.id >= X86_INS_JAE && inst.id <= X86_INS_JS;
		if (inst.id == X86_INS_JMP && inst.bytes[0] != 0xE9) isRelJump = false;
		if (isRelJump)
		{
			jumps.push_back({ i,numOriginBytes });
			numBytes += 12; //size of absolute jump in jump table
		}
		else if (inst.id == X86_INS_CALL)
		{
			calls.push_back({ i, numOriginBytes });
			numBytes += 14;
		}
		numOriginBytes += inst.size;
		numBytes += inst.size;
		numInstructions++;
		if (numOriginBytes >= 5) break;
	}
	*outGapPtr = &outBuffer[numOriginBytes];
	hook->stolenInstructionSize = numOriginBytes;
	numBytes += 12;
	//relative jumps need to be converted to absolute, 64 bit jumps
	//but since those require the destruction of a register, I'm going
	//to move that logic to the end of the stolen bytes (in case previous
	//instructions use that register). Rather than try to determine if each 
	//jump is relative or not, ALL jumps will go through the jump table
	
	//so in assembly, this is going to look like this: 
	/*		Old            |               NEW            
	 ----------------------|-----------------------------
		jmp 32			   |		jmp 2
		nop				   |		nop
		nop				   |		nop
						   |		mov rax, <Original Jmp Target>
						   |		jmp rax
	*/

	uint32_t jumpTablePos = numOriginBytes + 12;

	for (auto jmp : jumps)
	{
		cs_insn& instr = disassembledInstructions[jmp.first];
		char* jmpTargetAddr = instr.op_str;
		uint8_t distToJumpTable = jumpTablePos - (jmp.second + instr.size);

		//rewrite the operand for the jump to go to the jump table
		uint8_t instrByteSize = instr.bytes[0] == 0x0F ? 2 : 1;
		uint8_t operandSize = instr.size - instrByteSize;
		
		switch (operandSize)
		{
			case 1: instr.bytes[instrByteSize] = distToJumpTable; break;
			case 2: {uint16_t dist16 = distToJumpTable; memcpy(&instr.bytes[instrByteSize], &dist16, 2); } break;
			case 4: {uint32_t dist32 = distToJumpTable; memcpy(&instr.bytes[instrByteSize], &dist32, 4);} break;
		}
	
		uint64_t targetAddr = _strtoui64(jmpTargetAddr, NULL, 0);
		WriteAbsoluteJmpBytes(&outBuffer[jumpTablePos], (void*)targetAddr);
		
		jumpTablePos += 12;
	}

	for (auto call : calls)
	{
		cs_insn& instr = disassembledInstructions[call.first];
		char* callTarget = instr.op_str;
		uint8_t distToCallTable = jumpTablePos - (call.second + 2); //+2 because we're rewriting the call to be a 2 byte relative jump

		//calls need to be rewritten as relative jumps to the call table
		//but we want to preserve the length of the instruction, so pad with NOPs 
		uint8_t jmpBytes[2] = { 0xEB, 0x00 };
		memcpy(jmpBytes + 1, &distToCallTable, sizeof(distToCallTable));
		memset(instr.bytes, 0x90, instr.size);
		memcpy(instr.bytes, jmpBytes, sizeof(jmpBytes));

		int8_t distToGapPtr = (numOriginBytes) - (jumpTablePos + 14);
	
		memcpy(jmpBytes+1, &distToGapPtr, 1);
		//after the call, we need to jump to the jmp back to the target function, since the call will return into the call table

		uint64_t targetAddr = _strtoui64(callTarget, NULL, 0);
		uint8_t callSize = WriteAbsoluteCallBytes(&outBuffer[jumpTablePos], (void*)targetAddr);
		
		memcpy(&outBuffer[jumpTablePos+callSize], jmpBytes, sizeof(jmpBytes));
		jumpTablePos += 14;

	}

	uint32_t writePos = 0;
	for (int i = 0; i < numInstructions; ++i)
	{
		cs_insn inst = disassembledInstructions[i];
		memcpy(&outBuffer[writePos], inst.bytes, inst.size);
		writePos += inst.size;
	}
	cs_close(&handle);

	return numBytes;
}

void InstallHook(HookDesc* hook)
{
	DWORD oldProtect;
	check(VirtualProtect(hook->originalFunc, 1024, PAGE_EXECUTE_READWRITE, &oldProtect));

	uint8_t* jmpBackLoc = nullptr;
	
	uint8_t stolenBytes[1024];
	uint32_t numStolenBytes = BuildStolenByteBuffer(hook, stolenBytes, &jmpBackLoc, 1024);
	WriteAbsoluteJmpBytes(jmpBackLoc, (uint8_t*)hook->originalFunc + 5);
	
	//write trampoline func
	check(VirtualProtect(call_hook_payload, 1024, PAGE_EXECUTE_READWRITE, &oldProtect));
	WriteAbsoluteCallBytes( &((uint8_t*)call_hook_payload)[33], hook->payloadFunc);
	
	WriteAbsoluteJmpBytes((uint8_t*)hook->trampolineMem, hook->payloadFunc);


	//WriteAbsoluteCallBytes((uint8_t*)hook->trampolineMem, call_hook_payload);


	memcpy(&((uint8_t*)hook->trampolineMem)[12], stolenBytes, numStolenBytes);
	*hook->gatePtr = (void(*)(int,float))&(((uint8_t*)hook->trampolineMem)[12]);
	//write jumps
	WriteAbsoluteJump64(hook->longJumpMem, hook->trampolineMem);
	WriteRelativeJump(hook->originalFunc, hook->longJumpMem, hook->stolenInstructionSize - 5);
}

int main(int argc, const char** argv)
{	
	float y = atof(argv[0]);
//	CallTargetFunc(argc, (float)argc);
	HookDesc hook = { 0 };
	hook.originalFunc = CallTargetFunc;
	hook.gatePtr = &CallTargetGate;
	hook.payloadFunc = HookPayload;
	hook.longJumpMem = AllocatePageNearAddress(TargetFunc);
	hook.trampolineMem = AllocPage();

	InstallHook(&hook);

	//CallTargetFunc(argc-1, (float)argc);
//	CallTargetFunc(argc, (float)argc);
	CallTargetFunc(0, (float)argc);


}

