#include "hook-payload-messagebox.h"
#pragma comment (lib, "gdi32.lib")

HBRUSH showMessage(const LOGBRUSH* plbrush)
{
	MessageBox(NULL, "Function Hook", "Woohoo!", 0);
	return 0;
}