#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <functional>
#include <string>
#include <thread>
#include "capstone/x86.h"
#include "../hooking_common.h"
#include "capstone/capstone.h"
#include <vector>
#include <tlhelp32.h>

// Pass 0 as the targetProcessId to suspend threads in the current process
void SetOtherThreadsSuspended(bool suspend)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(THREADENTRY32);
		if (Thread32First(hSnapshot, &te))
		{
			do
			{
				if (te.dwSize >= (FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD))
					&& te.th32OwnerProcessID == GetCurrentProcessId()
					&& te.th32ThreadID != GetCurrentThreadId())
				{

					HANDLE thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
					if (thread != NULL)
					{
						if (suspend)
						{
							SuspendThread(thread);
						}
						else
						{
							ResumeThread(thread);
						}
						CloseHandle(thread);
					}
				}
			}
			while (Thread32Next(hSnapshot, &te));
		}
	}
}

__declspec(noinline) std::string NextHash(std::string s, int x)
{
	if (x > 0) return NextHash(s, x - 1);

	return std::to_string(std::hash<std::string>{}( s ));
}

void(*HookPayloadGate)(int, float) = nullptr;
__declspec(noinline) std::string NextHashHookPayload(std::string s, int x)
{
	return "Hook";
}

void CountingThreadMain()
{
	std::string val = "START";
	while (1)
	{
		val = NextHash(val, 5);
		printf("%s", val.c_str());
	}
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


int main()
{	
	for (int32_t i = 0; i < 1000; ++i)
	{
		std::thread countThread(CountingThreadMain);
		countThread.detach();
	}
 	
	HookDesc hook = { 0 };
	hook.originalFunc = NextHash;
	hook.gatePtr = &HookPayloadGate;
	hook.payloadFunc = NextHashHookPayload;
	hook.longJumpMem = AllocatePageNearAddress(NextHash);
	hook.trampolineMem = AllocPage();

	SetOtherThreadsSuspended(true);
	Sleep(1000.0f); //only for illustrative purposes, so you see the pause in the output when runnign the program
	InstallHook<void(*)(int, float)>(&hook);
	SetOtherThreadsSuspended(false);
	while (1) {};
	return 0;
}