//in order to support multiple hooks redirecting to the same payload, we need a method for getting the "right"
//trampoline in the payload function (ie, if foo and bar both are hooked to redirect to the same payload, that
//payload needs to call different trampolines, depending on whether it's going back to foo or bar).
//To do this, we need to rework what we consider a "trampoline" as. In this example, we're going to jump
//from the relay function directly to trampoline memory. The trampoline now contains "pre-payload" instructions, 
//followed by a jump to the payload code, and finally, regular trampoline logic. 

// Here's the plan:
//	1. Have relay functions jump to "pre-payload trampoline code", which pushes the address of the correct trampoline onto
//     a thread local stack. This means every hooked function gets a unique relay function
//
//  2. After pushing that onto the stack, we'll jump to the payload function body. This is trickier than it sounds because
//     we don't want the address push to mess with any of the function arguments for the payload, so we also have logic to
//     save the values in all the argument registers before calling PushAddress, and then other logic to restore these values
//     before the jump to the payload instructions.
//
//  3. Payload functions now have a required "Pop Address" variable to the payload code, which gets called just before 
//     executing the trampoline, which pops a trampoline address off this thread local stack. Using a stack like this 
//     allows payloads to call other hooked functions.
//
//  4. After calling PopAddress, payloads will call the trampoline as normal
//


#include "../hooking_common.h"
#include "../trampoline_common.h"
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <functional>
#include <string>
#include <thread>
#include "capstone/x86.h"
#include "capstone/capstone.h"
#include <vector>
#include <tlhelp32.h>
#include <functional>
#include <stack>
#include <map>
#include <thread>

class Dog
{
public:
	Dog(std::string inName) :
		name(inName)
	{
	}

	_declspec(noinline) void Bark() {
		printf("Barked\n");
	}
	_declspec(noinline) void RollOver(int x) { printf("Rolled Over %i times\n", x); }
	_declspec(noinline) void Sit() { printf("Sat Down\n"); }

public:
	std::string name;
};

//thread local assembly is gnarly, so let's let the compiler handle it, we'll just call these funcs
thread_local std::stack<uint64_t> hookJumpAddresses;

void PushAddress(uint64_t addr) //push the address of the jump target
{
	hookJumpAddresses.push(addr);
}

void PopAddress(uint64_t trampolinePtr)
{
	uint64_t addr = hookJumpAddresses.top();
	hookJumpAddresses.pop();
	memcpy((void*)trampolinePtr, &addr, sizeof(uint64_t));
}

//So here's the deal - we can't just insert a function call before the call to the payload to set a thread_local pointer back to the target function, 
//because payloads can call other hooked functions. We probably want to have a thread_local stack of function pointers, and have
//the trampoline pop the top of the stack and use that as the actual address to jump back to

thread_local void (*dogActionTrampoline)(Dog*);
void DogActionPayload(Dog* thisPtr)
{
	printf("%s: ", thisPtr->name.c_str());

	PopAddress(uint64_t(&dogActionTrampoline));
 	dogActionTrampoline(thisPtr);
}

thread_local void (*dogCountActionTrampoline)(Dog*, int);
void DogCountedActionPayload(Dog* thisPtr, int count)
{
	printf("%s: ", thisPtr->name.c_str());

	PopAddress(uint64_t(&dogCountActionTrampoline));
	dogCountActionTrampoline(thisPtr, count);
}

void InstallHook(void* func2hook, void* payloadFunc)
{
	SetOtherThreadsSuspended(true);

	DWORD oldProtect;
	VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

	//create the trampoline
	uint8_t* trampolineMem = (uint8_t*)AllocatePageNearAddress(func2hook); 
	uint32_t trampolineSize = BuildTrampoline(func2hook, (void*)(trampolineMem+102));

	uint8_t* memoryIter = (uint8_t*)trampolineMem;
	uint64_t trampolineAddress = (uint64_t)(memoryIter)+102;

	memoryIter += WriteSaveArgumentRegisters(memoryIter);
	memoryIter += WriteMovToRCX(memoryIter, trampolineAddress);
	memoryIter += WriteSubRSP32(memoryIter); //allocate home space for function call
	memoryIter += WriteAbsoluteCall64(memoryIter, &PushAddress);
	memoryIter += WriteAddRSP32(memoryIter);
	memoryIter += WriteRestoreArgumentRegisters(memoryIter);
	memoryIter += WriteAbsoluteJump64(memoryIter, payloadFunc);

	//create the relay function
	void* relayFuncMemory = AllocatePageNearAddress(func2hook);
	WriteAbsoluteJump64(relayFuncMemory, trampolineMem); //write relay func instructions

	//install the hook
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
	const int32_t relAddr = int32_t((int64_t)relayFuncMemory - ((int64_t)func2hook + sizeof(jmpInstruction)));
	memcpy(jmpInstruction + 1, &relAddr, 4);
	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));

	SetOtherThreadsSuspended(false);

}

//almost certainly specific to MSVC, lets you get a void*
//from a pointer to member function
template<typename FuncSig>
inline void* GetFuncPointer(FuncSig func)
{
	char** ptrptr = (char**)(&func);
	return (void*)(*ptrptr);
}

#pragma optimize(off, "")
int main()
{
	Dog snoopy("snoopy");
	Dog dogbert("dogbert");

	printf("Before Hook Installed:\n");
	snoopy.Bark();
	dogbert.RollOver(5);
	dogbert.Bark();
	snoopy.Sit();
	printf("\nNote that we can't tell which dog did what. So let's install a hook to output the dog name before each action.\n\n");

	{
		void* func2hook = GetFuncPointer< void(Dog::*)()>(&Dog::Bark);
		InstallHook(func2hook, DogActionPayload);
	}
	{
		void* func2hook = GetFuncPointer< void(Dog::*)()>(&Dog::Sit);
		InstallHook(func2hook, DogActionPayload);
	}
	{
		void* func2hook = GetFuncPointer< void(Dog::*)(int)>(&Dog::RollOver);
		InstallHook(func2hook, DogCountedActionPayload);
	}

	printf("After Hook Installed: \n");
	snoopy.Bark();
	dogbert.RollOver(5);
	dogbert.Bark();
	snoopy.Sit();

	return 0;
}