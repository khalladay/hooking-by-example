/*
	Trampoline-embdedded-disasm-same-process

	This program demonstrates how to use an disassembler (in this case, the capstone library) to
	build trampolines for a function in a program WITHOUT having prior knowledge of the compiled
	assembly for that function. 

*/

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
		case 1: printf("1 args %f\n", y); break;
		default:printf(">1 args\n"); break;
	}
}

_declspec(noinline) void CallTargetFunc(int x, float y)
{
	if (x > 0) CallTargetFunc(x-1, y);
	TargetFunc(x, y);
	printf("Calling with x: %i y: %f \n", x, y);
}


//this hardcoded gate function pointer could be replaced with something like a giant array of HookDescs that all contain gatePtrs
//and have the pre-hookpayload hook code set an ID for the currently active hook, then have the HookPayload func use that id to get the
//appropriate gate function pointer out of the global hook array. thread_local issues apply. 
void(*CallTargetGate)(int, float) = nullptr;
void HookPayload(int x, float y)
{
	printf("Hook Executed\n");

	//the function being hooked (CallTargetFunc) is recursive, so we need to make sure 
	//that we only replace the arguments for the first call in a sequence
	//thread_local not technically needed here since we only have one thread, but included 
	//to show off how this could work in a multi-threaded project
	thread_local static int recurseGuard = 0;

	if (!recurseGuard)
	{
		recurseGuard = 1;
		CallTargetGate(5, y);
	}
	else
	{
		CallTargetGate(x, y);
	}
	recurseGuard = 0;
}

struct HookDesc
{
	void* originalFunc;
	void(**gatePtr)(int, float);
	void* payloadFunc;
	void* trampolineMem;
	void* longJumpMem;

	uint8_t stolenInstructionSize;
};

uint32_t BuildFunctionGate(HookDesc* hook, uint8_t* outBuffer, uint32_t outBufferSize)
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
	uint32_t numTotalBytes = 0;
	uint32_t numStolenBytes = 0;
	std::vector<std::pair<uint32_t, uint32_t>> jumps;
	std::vector<std::pair<uint32_t, uint32_t>> calls;
	uint32_t numInstructions = 0;

	for (int i = 0; i < count; ++i)
	{
		cs_insn inst = disassembledInstructions[i];
		
		//all condition jumps are relative, as are all E9 jmps. non-E9 "jmp" is absolute, so no need to deal with it
		bool isRelJump = inst.id >= X86_INS_JAE && 
						 inst.id <= X86_INS_JS &&
						 !(inst.id == X86_INS_JMP && inst.bytes[0] != 0xE9);

		if (isRelJump)
		{
			jumps.push_back({ i,numStolenBytes });
			numTotalBytes += 13; //size of absolute jump in jump table
		}
		else if (inst.id == X86_INS_CALL)
		{
			calls.push_back({ i, numStolenBytes });
			numTotalBytes += 15; //sizeof an absoluate call in the call table + a 2 byte jump to the end of the gate bytes
		}

		numStolenBytes += inst.size;
		numTotalBytes += inst.size;
		numInstructions++;
		if (numStolenBytes >= 5) break;
	}

	//immediately after the stolen bytes (but BEFORE the jump/call tables), we need to add an
	//absolute jump back to the origin function
	hook->stolenInstructionSize = numStolenBytes;
	numTotalBytes += 13;
	WriteAbsoluteJump64(&outBuffer[numStolenBytes], (uint8_t*)hook->originalFunc + numStolenBytes);

	//now we need to construct the call and jump tables, and rewrite any jmp/call instructions
	//in the stolen bytes to use them instead. This is to account for jmp/call instructions in 
	//the stolen bytes that use relative values in their operands. Since we've relocated these
	//instructions into the function gate, these relative values are no longer correct. These
	//jumps/calls still need to be able to get to the correct place in the origin function, so 
	//they need to be rewritten as absolute jumps (there's no guarantee the function gate will be
	//close enough in memory to use relative instructions at all)

	//absolute jumps require the destruction of a register, so we can't just insert them into the
	//function gate logic, since that logic might use that register for something else. Instead, we'll
	//add these absolute jumps/calls after the function gate, and convert the jumps/calls in the gate
	//logic to jumps to the appropriate place in this appended list of instructions. 

	uint32_t jumpTablePos = numStolenBytes + 13;
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
		WriteAbsoluteJump64(&outBuffer[jumpTablePos], (void*)targetAddr);
		
		jumpTablePos += 13;
	}

	for (auto call : calls)
	{
		cs_insn& instr = disassembledInstructions[call.first];
		char* callTarget = instr.op_str;
		uint8_t distToCallTable = jumpTablePos - (call.second + 2); //+2 because we're rewriting the call to be a 2 byte relative jump

		//calls need to be rewritten as relative jumps to the call table
		//but we want to preserve the length of the instruction, so pad with NOPs 
		uint8_t jmpBytes[2] = { 0xEB, distToCallTable };
		memset(instr.bytes, 0x90, instr.size);
		memcpy(instr.bytes, jmpBytes, sizeof(jmpBytes));

		uint64_t targetAddr = _strtoui64(callTarget, NULL, 0);
		uint32_t callSize = WriteAbsoluteCall64(&outBuffer[jumpTablePos], (void*)targetAddr);
		
		//after the call, we need a jump back to the end of the function gate in order to jump back to the origin function
		jmpBytes[1] = (numStolenBytes) - (jumpTablePos + 14);
		memcpy(&outBuffer[jumpTablePos+callSize], jmpBytes, sizeof(jmpBytes));

		jumpTablePos += 15;
	}

	uint32_t writePos = 0;
	for (int i = 0; i < numInstructions; ++i)
	{
		cs_insn inst = disassembledInstructions[i];
		memcpy(&outBuffer[writePos], inst.bytes, inst.size);
		writePos += inst.size;
	}
	cs_close(&handle);

	return numTotalBytes;
}

template<typename FunctionSignature>
void InstallHook(HookDesc* hook)
{
	DWORD oldProtect;
	check(VirtualProtect(hook->originalFunc, 1024, PAGE_EXECUTE_READWRITE, &oldProtect));
	
	uint8_t functionGateBytes[1024];
	uint32_t functionGateSize = BuildFunctionGate(hook, functionGateBytes, 1024);

	//first, let's write out the trampoline, which consists of a jump to the hook payload
	//followed by the function gate
	uint32_t jumpSize = WriteAbsoluteJump64((uint8_t*)hook->trampolineMem, hook->payloadFunc);
	memcpy(&((uint8_t*)hook->trampolineMem)[jumpSize], functionGateBytes, functionGateSize);
	*hook->gatePtr = reinterpret_cast<FunctionSignature> (&(((uint8_t*)hook->trampolineMem)[jumpSize]));

	//finally, write the jumps needed to get to the trampoline from the origin function
	WriteAbsoluteJump64(hook->longJumpMem, hook->trampolineMem);
	WriteRelativeJump(hook->originalFunc, hook->longJumpMem, hook->stolenInstructionSize - 5);
}

int main(int argc, const char** argv)
{	
	HookDesc hook = { 0 };
	hook.originalFunc = CallTargetFunc;
	hook.gatePtr = &CallTargetGate;
	hook.payloadFunc = HookPayload;
	hook.longJumpMem = AllocatePageNearAddress(TargetFunc);
	hook.trampolineMem = AllocPage();
	InstallHook<void(*)(int, float)>(&hook);
	CallTargetFunc(10, (float)argc);
}

