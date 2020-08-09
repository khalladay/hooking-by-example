//this is a simple program used to test methods for installing 
//a hook in a different process. The idea is for another process to 
//hook the getNum functions of this app, to cause it to output a different
//value to the console from the while loop in main

//I've left debug symbols on in the project file for this example,
//so it's possible to find getNum by symbol name

#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>

#define DLL_NAME "getnum-dll.dll"
#define DLL_FUNC_NAME "getNum"

//hacky way to get the path to the correct dll for
//whatever the active build config is... saves having to 
//provide the path on the command line, but is otherwise
//not particularly important
void GetPathToDLL(char* outPath, size_t outPathSize)
{
	char relPath[1024];
	char thisAppName[1024];
	GetModuleFileName(NULL, relPath, 1024);
	GetModuleBaseName(GetCurrentProcess(), NULL, thisAppName, 1024);
	char* replaceStart = strstr(relPath, thisAppName);
	const char* dllName = DLL_NAME;
	memcpy(replaceStart, dllName, strlen(dllName));
	memset(replaceStart + strlen(dllName), '\0', &relPath[1024] - (replaceStart + strlen(dllName)));

	_fullpath(outPath, relPath, outPathSize);
}

int main()
{
	char dllPath[1024];
	GetPathToDLL(dllPath, 1024);
	
	HMODULE sharedLib = LoadLibrary(dllPath);
	int(*getNum)() = (int(*)()) GetProcAddress(sharedLib, DLL_FUNC_NAME);

	while (1)
	{
		printf("GetNum: %i\n", getNum());
		Sleep(5000);
	}
	return 0;
}