#include "../hooking_common.h"
#include "../trampoline_common.h"
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#include <tlhelp32.h>

// Pass 0 as the targetProcessId to suspend threads in the current process

__declspec(noinline) std::string NextHash(std::string s, int x)
{
	if (x > 0) return NextHash(s, x - 1);

	return std::to_string(std::hash<std::string>{}(s));
}

void(*NextHashTrampoline)(int, float) = nullptr;
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

void _SetOtherThreadsSuspended(bool suspend)
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
			} while (Thread32Next(hSnapshot, &te));
		}
	}
}

void InstallHook(void* func2hook, void* payloadFunc, void** trampolinePtr)
{
	_SetOtherThreadsSuspended(true);

	DWORD oldProtect;
	VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	void* hookMemory = AllocatePageNearAddress(func2hook);

	//create the trampoline
	uint32_t trampolineSize = BuildTrampoline(func2hook, hookMemory);

	//Allocate executable memory for the trampoline
	*trampolinePtr = hookMemory;

	//create the relay function
	void* relayFuncMemory = (char*)hookMemory + trampolineSize;
	WriteAbsoluteJump64(relayFuncMemory, payloadFunc); //write relay func instructions

	//install the hook
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
	const int32_t relAddr = int32_t((int64_t)relayFuncMemory - ((int64_t)func2hook + sizeof(jmpInstruction)));
	memcpy(jmpInstruction + 1, &relAddr, 4);
	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));

	_SetOtherThreadsSuspended(false);
}


int main()
{
	for (int32_t i = 0; i < 1000; ++i)
	{
		std::thread countThread(CountingThreadMain);
		countThread.detach();
	}
	
	//the call to SetOtherThreadsSuspended and Sleep here are
	//only for illustrative purposes, so you see the pause in the output when runnign the program
	//the real use case for them is inside InstallHook() (shown above)
	_SetOtherThreadsSuspended(true);
	Sleep(1000); 
	InstallHook(NextHash, NextHashHookPayload, (void**)&NextHashTrampoline);
	_SetOtherThreadsSuspended(false);
	
	while (1) {};
	return 0;
}