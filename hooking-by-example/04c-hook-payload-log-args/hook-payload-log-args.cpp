#include "hook-payload-log-args.h"
#include <stdio.h>
#pragma comment (lib, "gdi32.lib")


HBRUSH showMessage(const LOGBRUSH* plbrush)
{
	COLORREF brushCol = plbrush->lbColor;
	ULONG_PTR hatch = plbrush->lbHatch;
	UINT style = plbrush->lbStyle;

	printf("CreateBrushIndirectCalled\n\t"
		"COLOR: %x %x %x\n\t"
		"HATCH: %llu\n\t"
		"STYLE: %u\n",
		GetRValue(brushCol), GetGValue(brushCol), GetBValue(brushCol), hatch, style
	);
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD ul_reason_for_call, LPVOID lpvReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		AllocConsole();
		AttachConsole(GetCurrentProcessId());
		FILE* pCout;
		freopen_s(&pCout, "conout$", "w", stdout);
		freopen_s(&pCout, "conin$", "w", stdin);
		freopen_s(&pCout, "conout$", "w", stderr);
		fclose(pCout);
		break;
	}
	return true;
}