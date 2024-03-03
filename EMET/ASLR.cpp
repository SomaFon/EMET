#include"ASLR.h"

DWORD BottomUpASLR() {
	DWORD dwPid = GetCurrentProcessId();
	DWORD dwSeed = GetTickCount() ^ dwPid;
	RTLRANDOM pRtlRandom = (RTLRANDOM)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "RtlRandom");
	DWORD dwRandomVal = pRtlRandom(&dwSeed);
	while (dwRandomVal) {
		proxy_NtAllocateVirtualMemory(0, 0x10000);
		dwRandomVal--;
	}
	return 0;
}

DWORD MandatoryASLR(PHOOKINFO HookInfo) {
	DWORD dwRet = 0;
	//NtMapViewOfSection
	if (HookInfo->dwIndexApi - 50) {
		dwRet = Proxy_ApiCaller(HookInfo->dwArgc, HookInfo->dwArgAddr, HookInfo->dwTrueApiAddr);
		//dwRet == STATUS_SUCCESS»òSTATUS_IMAGE_NOT_AT_BASE
		if (dwRet == 0 || dwRet == 0x40000003) {
			MEMORY_BASIC_INFORMATION MemInfo = { 0 };
			PVOID BaseAddr = (PVOID)*(HookInfo->ApiArg + 2);
			SIZE_T ViewSize = (SIZE_T)*(HookInfo->ApiArg + 6);
			if (VirtualQuery(BaseAddr, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION))) {
				if (MemInfo.Type == MEM_IMAGE && IsReloadNeeded((DWORD_PTR)BaseAddr)) {
					HANDLE hProcess = (HANDLE)*(HookInfo->ApiArg + 1);
					NTUNMAPVIEWOFSECTION pNtUnmapViewofSection = (NTUNMAPVIEWOFSECTION)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtUnmapViewofSection");
					pNtUnmapViewofSection(hProcess, BaseAddr);
					proxy_NtAllocateVirtualMemory(BaseAddr, ViewSize);//Õ¼¿Ó
					dwRet = Proxy_ApiCaller(HookInfo->dwArgc, HookInfo->dwArgAddr, HookInfo->dwTrueApiAddr);
				}
			}
		}
	}
	//NtUnmapViewOfSection
	else {
		dwRet = Proxy_ApiCaller(HookInfo->dwArgc, HookInfo->dwArgAddr, HookInfo->dwTrueApiAddr);
	}

	return dwRet;
}
