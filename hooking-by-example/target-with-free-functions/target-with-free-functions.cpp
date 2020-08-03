//this is a simple program used to test methods for installing 
//a hook in a different process. The idea is for another process to 
//hook the getNum functions of this app, to cause it to output a different
//value to the console from the while loop in main

//I've left debug symbols on in the project file for this example,
//so it's possible to find getNum by symbol name

#include <stdio.h>
#include <Windows.h>

__declspec(noinline) int getNum()
{
	return 55;
}

int main()
{
	while (1)
	{
		printf("GetNum: %i\n", getNum());
		Sleep(5000);
	}
	return 0;
}