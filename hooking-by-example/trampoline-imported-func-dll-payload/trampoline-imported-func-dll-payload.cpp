#include "trampoline-imported-func-dll-payload.h"
#include <stdio.h>
#include <stack>
#include <vector>
#include "capstone/x86.h"
#include "../hooking_common.h"
#include "capstone/capstone.h"



#define TARGET_APP_NAME "target-with-functions-from-dll.exe"
#define DLL_NAME "getnum-dll.dll"
#define FUNC2HOOK_NAME "getNum"

/**************************
 * HOOKING CODE           *
 **************************/
struct HookDesc
{
	void* originalFunc;
	void* payloadFunc;
	void* trampolineMem;
	void* longJumpMem;

	uint8_t stolenInstructionSize;
};

thread_local std::stack<uint64_t> hookJumpAddresses;

void PushAddress(uint64_t addr) //push the address of the jump target
{
	hookJumpAddresses.push(addr);
}

void PopAddress(uint64_t gatePointer)
{
	uint64_t addr = hookJumpAddresses.top();
	hookJumpAddresses.pop();
	memcpy((void*)gatePointer, &addr, sizeof(uint64_t));
}

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
			numTotalBytes += 12; //size of absolute jump in jump table
		}
		else if (inst.id == X86_INS_CALL)
		{
			calls.push_back({ i, numStolenBytes });
			numTotalBytes += 14; //sizeof an absoluate call in the call table + a 2 byte jump to the end of the gate bytes
		}

		numStolenBytes += inst.size;
		numTotalBytes += inst.size;
		numInstructions++;
		if (numStolenBytes >= 5) break;
	}

	//immediately after the stolen bytes (but BEFORE the jump/call tables), we need to add an
	//absolute jump back to the origin function
	hook->stolenInstructionSize = numStolenBytes;
	numTotalBytes += 12;
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

	uint32_t jumpTablePos = numStolenBytes + 12;
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
		case 4: {uint32_t dist32 = distToJumpTable; memcpy(&instr.bytes[instrByteSize], &dist32, 4); } break;
		}

		uint64_t targetAddr = _strtoui64(jmpTargetAddr, NULL, 0);
		WriteAbsoluteJump64(&outBuffer[jumpTablePos], (void*)targetAddr);

		jumpTablePos += 12;
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
		jmpBytes[1] = (numStolenBytes)-(jumpTablePos + 14);
		memcpy(&outBuffer[jumpTablePos + callSize], jmpBytes, sizeof(jmpBytes));

		jumpTablePos += 14;
	}

	uint32_t writePos = 0;
	for (uint32_t i = 0; i < numInstructions; ++i)
	{
		cs_insn inst = disassembledInstructions[i];
		memcpy(&outBuffer[writePos], inst.bytes, inst.size);
		writePos += inst.size;
	}
	cs_close(&handle);

	return numTotalBytes;
}

void InstallHook(void* targetFunc, void* payloadFunc)
{
	HookDesc hook = { 0 };
	hook.originalFunc = targetFunc;
	hook.payloadFunc = payloadFunc;
	hook.trampolineMem = AllocPage();
	hook.longJumpMem = AllocatePageNearAddress(targetFunc);


	SetOtherThreadsSuspended(true);

	DWORD oldProtect;
	check(VirtualProtect(hook.originalFunc, 1024, PAGE_EXECUTE_READWRITE, &oldProtect));

	uint8_t functionGateBytes[1024];
	uint32_t functionGateSize = BuildFunctionGate(&hook, functionGateBytes, 1024);

	uint8_t* trampolineIter = (uint8_t*)hook.trampolineMem;

	uint64_t gateFuncAddress = (uint64_t)(trampolineIter)+100;

	trampolineIter += WriteSaveArgumentRegisters(trampolineIter);
	trampolineIter += WriteMovToRCX(trampolineIter, gateFuncAddress);
	trampolineIter += WriteSubRSP32(trampolineIter); //allocate home space for function call
	trampolineIter += WriteAbsoluteCall64(trampolineIter, &PushAddress);
	trampolineIter += WriteAddRSP32(trampolineIter);
	trampolineIter += WriteRestoreArgumentRegisters(trampolineIter);
	trampolineIter += WriteAbsoluteJump64(trampolineIter, hook.payloadFunc);
	memcpy(trampolineIter, functionGateBytes, functionGateSize);

	//finally, write the jumps needed to get to the trampoline from the origin function
	WriteAbsoluteJump64(hook.longJumpMem, hook.trampolineMem);
	WriteRelativeJump(hook.originalFunc, hook.longJumpMem, hook.stolenInstructionSize - 5);
	SetOtherThreadsSuspended(false);
}

/**************************
 * PAYLOAD CODE           *
 **************************/

int getNumPayload()
{
	//this payload is used with the demo program "trampoline-imported-func-with-dll-injection
	//and is meant to be injected into the target app "target-with-functions-from-dll"
	//this payload hooks the "getNum" function found in the "getnum-dll" project
	printf("Trampoline Executed\n");

	int(*target)() = nullptr;
	PopAddress(uint64_t(&target));
	return target();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD ul_reason_for_call, LPVOID lpvReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		HMODULE mod = FindModuleInProcess(GetCurrentProcess(), DLL_NAME);

		void* localHookFunc = GetProcAddress(mod, FUNC2HOOK_NAME);
		InstallHook(localHookFunc,getNumPayload);
	}
	return true;
}