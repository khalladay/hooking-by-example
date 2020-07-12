//this is a simple program used to test methods for installing 
//a hook in a different process. The idea is for another process to 
//hook the getNum function of this app, to cause it to output a different
//value to the console from the while loop in main

#include <stdio.h>
#include <Windows.h>

extern "C"
{
#pragma optimize("", off)
	int getNum()
	{
		return 99;
	}
#pragma optimize("", on)
}

int main()
{
	while (1)
	{
		int x = getNum();
		printf("The Number is %i\n", x);
		Sleep(2000);
	}
	return 0;
}