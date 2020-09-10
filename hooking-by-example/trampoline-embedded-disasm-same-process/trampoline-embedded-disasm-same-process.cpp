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

_declspec(noinline) void CallTargetFunc(int x, float y)
{
	TargetFunc(x, y);
	printf("Target func called\n");
}



struct HookDesc
{
	void* originalFunc;
	void* payloadFunc;
	void* trampolineMem;
	void* longJumpMem;

	uint8_t stolenInstructionCount;
	uint8_t stolenInstructionSize;
};

extern "C" void call_hook_payload();

#pragma optimize("", off)
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
		printf("%s %s\n", inst.mnemonic, inst.op_str);
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
	numOriginBytes += 12; //enough for the jmp back to the original function 
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

	uint32_t jumpTablePos = numOriginBytes;

	for (auto jmp : jumps)
	{
		cs_insn& instr = disassembledInstructions[jmp.first];
		char* jmpTargetAddr = instr.op_str;
		uint8_t distToJumpTable = jumpTablePos - (jmp.second + instr.size);

		//there's so many different jump opcodes, that it makes totally replacing the instruction bytes untenable
		//instead, we'll just rewrite the operand for the jump to go to the jump table
		uint8_t instrByteSize = instr.bytes[0] == 0x0F ? 2 : 1;
		uint8_t operandSize = instr.size - instrByteSize;
		
		switch (operandSize)
		{
		case 1: instr.bytes[instrByteSize] = distToJumpTable; break;
		case 2: {uint16_t dist16 = distToJumpTable; memcpy(&instr.bytes[instrByteSize], &dist16, 2); } break;
		case 4: {uint32_t dist32 = distToJumpTable; memcpy(&instr.bytes[instrByteSize], &dist32, 4);} break;
		}
	
		uint8_t jmpBytes[] = { 0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //movabs into rax
								0xFF, 0xE0 }; //jmp rax
		uint64_t targetAddr = _strtoui64(jmpTargetAddr, NULL, 0);
		memcpy(&jmpBytes[2], &targetAddr, 8);
		memcpy(&outBuffer[jumpTablePos], jmpBytes, sizeof(jmpBytes));
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

		//(numOriginBytes-12) to get the the mov rax <addr> of the gap pointer jump
		int8_t distToGapPtr = (numOriginBytes - 12) - (jumpTablePos + 14);

		uint8_t callBytes[] = {	0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //movabs 64 bit value into rax
									0xFF, 0xD0, //call rax
									0xEB, 0x00 //jmp back to immediately before jump/call table
								};
	

		memcpy(&callBytes[13], &distToGapPtr, 1);
		//after the call, we need to jump to the jmp back to the target function, since the call will return into the call table

		uint64_t targetAddr = _strtoui64(callTarget, NULL, 0);
		memcpy(&callBytes[2], &targetAddr, 8);
		memcpy(&outBuffer[jumpTablePos], callBytes, sizeof(callBytes));
		jumpTablePos += 14;

	}

	//similarly, all calls will be converted to relative jumps into a call table

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
	bool err = VirtualProtect(hook->originalFunc, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	uint8_t stolenBytes[1024];
	uint8_t* jmpBackLoc = nullptr;
	uint32_t numStolenBytes = BuildStolenByteBuffer(hook, stolenBytes, &jmpBackLoc, 1024);

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

	memcpy(jmpBackLoc, jmpBytes, sizeof(jmpBytes));
	
	memcpy(trampolineBytePtr, stolenBytes, numStolenBytes);
	trampolineBytePtr += numStolenBytes;
	
	//write jumps
	WriteAbsoluteJump64(hook->longJumpMem, hook->trampolineMem);
	WriteRelativeJump(hook->originalFunc, hook->longJumpMem, hook->stolenInstructionSize - 5);

}

int main(int argc, const char** argv)
{	
	float y = atof(argv[0]);
	CallTargetFunc(argc, (float)argc);
	HookDesc hook = { 0 };
	hook.originalFunc = CallTargetFunc;
	hook.payloadFunc = HookPayload;
	hook.longJumpMem = AllocatePageNearAddress(TargetFunc);
	hook.trampolineMem = AllocPage();

	InstallHook(&hook);

	CallTargetFunc(argc-1, (float)argc);
	CallTargetFunc(argc, (float)argc);
	CallTargetFunc(argc+1, (float)argc);


}

