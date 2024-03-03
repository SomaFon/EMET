
#include"SEHOP.h"


typedef NTSTATUS(NTAPI *LPFN_FINALEXCEPTIONHANDLER)(int a1, int a2, int a3, int a4);

LPFN_FINALEXCEPTIONHANDLER __FinalExceptionHandler = 0;
#define EXCEPTION_CHAIN_END ((struct _EXCEPTION_REGISTRATION_RECORD * POINTER_32)-1)

LPFN_NTQUERYINFORMATIONPROCESS _NtQueryInformationProcess = NULL;

BOOL SEHOPChecker(PEXCEPTION_POINTERS ExceptionInfo)
{
	HMODULE ModuleHandle = NULL;
	LONG                      Status;
	if (__FinalExceptionHandler == NULL)
	{
		ModuleHandle = GetModuleHandleA("Ntdll.dll");
	}
	if (ModuleHandle == NULL)
	{
		return FALSE;
	}
	if (_NtQueryInformationProcess == NULL)
	{
		_NtQueryInformationProcess = (LPFN_NTQUERYINFORMATIONPROCESS)GetProcAddress(ModuleHandle, "NtQueryInformationProcess");
		if (_NtQueryInformationProcess == NULL)
		{
			return FALSE;
		}
	}


	IMAGE_DOS_HEADER* ImageDosHeader = NULL;
	IMAGE_OPTIONAL_HEADER*  ImageOptionalHeader = NULL;
	ImageDosHeader = (IMAGE_DOS_HEADER *)ModuleHandle;
	ImageOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((BYTE*)ModuleHandle + ImageDosHeader->e_lfanew + 24);

	__FinalExceptionHandler = LPFN_FINALEXCEPTIONHANDLER(ImageOptionalHeader->ImageBase + 0xc72ff);


	if (__FinalExceptionHandler == NULL)
	{
		return FALSE;
	}

	PVOID ExceptionAddress = ExceptionInfo->ExceptionRecord->ExceptionAddress;
	PEXCEPTION_REGISTRATION_RECORD SEHPointer = (PEXCEPTION_REGISTRATION_RECORD)__readfsdword(0);
	int ExecuteFlags;
	ULONG HighAddress;

	bool IsExceptionChainValid = 1;
	if (_NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)34, &ExecuteFlags, sizeof(ExecuteFlags), 0) == 0 && (ExecuteFlags & 0x40) != 0)
	{
		IsExceptionChainValid = 0;
	}

	PNT_TIB Tib = (_NT_TIB*)NtCurrentTeb();
	if (IsExceptionChainValid) {

		while (SEHPointer->Next != EXCEPTION_CHAIN_END)
		{
			HighAddress = (ULONG)SEHPointer + sizeof(EXCEPTION_REGISTRATION_RECORD);
			if ((PVOID)SEHPointer > Tib->StackBase || HighAddress < ULONG(Tib->StackLimit))
				goto corruption;
			if (((ULONG)SEHPointer & 3) != 0)
				goto corruption;
			if (((PVOID)SEHPointer->Handler >= Tib->StackLimit) && ((ULONG)SEHPointer->Handler < ULONG(Tib->StackBase)))
				goto corruption;

		}
		if ((*((int *)NtCurrentTeb() + 0xFCA) & 0x200) != 0 && SEHPointer->Handler != (PEXCEPTION_ROUTINE)__FinalExceptionHandler)
		{
			goto corruption;
		}

	}
corruption:
	TerminateProcess(GetCurrentProcess(), 0);
	return FALSE;

}
