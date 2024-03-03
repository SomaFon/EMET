#include <Winternl.h>//Native API
#include <ntstatus.h>//Native API

#include"DEP.h"
LPFN_NTSETINFORMATIONPROCESS __NtSetInformationProcess = 0;

BOOL OpenDEP() {
	DWORD dwFlag = 0;
	BOOL bPerManent = FALSE;
	BOOL bRet = GetProcessDEPPolicy(GetCurrentProcess(), &dwFlag, &bPerManent);
	if (bRet) {
		if (!dwFlag & PROCESS_DEP_ENABLE) {
			dwFlag = PROCESS_DEP_ENABLE;
		}
		bRet = SetProcessDEPPolicy(dwFlag);
	}
	return bRet;
}

BOOL CloseDEP() {
	DWORD dwFlag = 0;
	BOOL bPerManent = FALSE;
	BOOL bRet = GetProcessDEPPolicy(GetCurrentProcess(), &dwFlag, &bPerManent);
	if (bRet) {
		if (dwFlag & PROCESS_DEP_ENABLE) {
			dwFlag = 0;
		}
		bRet = SetProcessDEPPolicy(dwFlag);
	}
	return bRet;
}


BOOL OpenDEPByNTAPI() {
	HMODULE ModuleHandle = NULL;
	LONG                      Status;
	if (__NtSetInformationProcess == NULL)
	{
		ModuleHandle = GetModuleHandle(_T("Ntdll.dll"));
		if (ModuleHandle == NULL)
		{
			return FALSE;
		}
		__NtSetInformationProcess = (LPFN_NTSETINFORMATIONPROCESS)GetProcAddress(ModuleHandle, "NtSetInformationProcess");
		if (__NtSetInformationProcess == NULL)
		{
			return FALSE;
		}
	}

	ULONG ExecuteFlags = MEM_EXECUTE_OPTION_DISABLE;
	Status = __NtSetInformationProcess(
		GetCurrentProcess(), // (HANDLE)-1 
		(PROCESSINFOCLASS)0x22, // 0x22 
		&ExecuteFlags, // ptr to 0x1 
		sizeof(ExecuteFlags)); // 0x4

	if (Status == STATUS_SUCCESS) {
		return TRUE;
	}
	else return FALSE;
}


BOOL CloseDEPByNTAPI() {
	HMODULE ModuleHandle = NULL;
	LONG                      Status;
	if (__NtSetInformationProcess == NULL)
	{
		ModuleHandle = GetModuleHandle(_T("Ntdll.dll"));
		if (ModuleHandle == NULL)
		{
			return FALSE;
		}
		__NtSetInformationProcess = (LPFN_NTSETINFORMATIONPROCESS)GetProcAddress(ModuleHandle, "NtSetInformationProcess");
		if (__NtSetInformationProcess == NULL)
		{
			return FALSE;
		}
	}

	ULONG ExecuteFlags = MEM_EXECUTE_OPTION_ENABLE;
	Status = __NtSetInformationProcess(
		GetCurrentProcess(), // (HANDLE)-1 
		(PROCESSINFOCLASS)0x22, // 0x22 
		&ExecuteFlags, // ptr to 0x2 
		sizeof(ExecuteFlags)); // 0x4

	if (Status == STATUS_SUCCESS) {
		return TRUE;
	}
	else return FALSE;
}

