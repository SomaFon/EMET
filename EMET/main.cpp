#include "EMET.h"


int main()
{
	
	InitializeEMET();
	ApllyEMET();
	HMODULE ModuleBase = LoadLibraryA("mshtml.dll");
	DWORD Test = *(DWORD*)ModuleBase;
	//BottomUpASLR();

	//DWORD_PTR ModuleBase = (DWORD_PTR)GetModuleHandleA("ntdll.dll");
	//DWORD Test = *(DWORD*)(GetModuleEAT(ModuleBase));
	//Test = *(DWORD*)(GetModuleEAT(ModuleBase));

	//system("pause");
 	return 0;
}