#include "EAF.h"
extern GLOBALINFO g_Info;
extern CRITICAL_SECTION g_CriSec;
NTPROTECTVIRTUALMEMORY pNtProtectVirtualMemory = (NTPROTECTVIRTUALMEMORY)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtProtectVirtualMemory");
const TCHAR* __g_ModuleNames[] = { _T("ntdll.dll"), _T("kernel32.dll"),_T("kernelbase.dll"),_T("EMET.exe") };

//开启EAF
DWORD EAF() {
	DWORD dwRet = 0;
	EnterCriticalSection(&g_CriSec);

	for (int i = 0; i < 3; i++) {
		DWORD_PTR ModuleBase = (DWORD_PTR)GetModuleHandle(LPCTSTR(g_Info.SystemDllInfo[i].dwModuleName));
		g_Info.SystemDllInfo[i].dwModuleBase = ModuleBase;
		g_Info.SystemDllInfo[i].dwEATAddr = GetModuleEAT(ModuleBase);
		g_Info.SystemDllInfo[i].dwModuleSize = GetModuleSize(ModuleBase);
		g_Info.SystemDllInfo[i].dwPageAddrOfEAT = g_Info.SystemDllInfo[i].dwEATAddr & 0xFFFFF000;
		g_Info.SystemDllInfo[i].dwSize = 0x1000;

		MEMORY_BASIC_INFORMATION mbi;
		VirtualQuery((PVOID)g_Info.SystemDllInfo[i].dwEATAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		if (mbi.State == MEM_COMMIT)
		{
			if (!(mbi.Protect & PAGE_GUARD))
			{
				DWORD NewProtect = 0;
				DWORD OldProtect = 0;
				DWORD dwSize = g_Info.SystemDllInfo[i].dwSize;
				PVOID dwBaseAddress = (PVOID)g_Info.SystemDllInfo[i].dwPageAddrOfEAT;
				NewProtect = mbi.Protect | PAGE_GUARD;
				g_Info.SystemDllInfo[i].dwProtect = NewProtect;
				dwRet = pNtProtectVirtualMemory(GetCurrentProcess(), &dwBaseAddress, &dwSize, NewProtect, &OldProtect);	
			}
		}
	}
	LeaveCriticalSection(&g_CriSec);
	return dwRet;
}

//在加载目标模块时默认开启EAF_Plus
void EAF_PLUS(UNION_HOOKEDFUNCINFO::PEAFP_INFO pMemProt, HMODULE hModuleBase) {
	char szFileName[0x1000];
	if (pMemProt->dwType == 4 && hModuleBase != NULL) {
		if (GetModuleFileNameA(hModuleBase, szFileName, 0x1000)) {
			//获得加载的文件名
			char *pszCurLoadingFileName = strrchr(szFileName, '\\');
			if (pszCurLoadingFileName != NULL) {
				pszCurLoadingFileName += 1;
			}
			else {
				pszCurLoadingFileName = szFileName;
			}
			for (int i = 3; i < 13; i++) {
				DWORD dwModuleName = g_Info.SystemDllInfo[i].dwModuleName;
				if (dwModuleName == 0) break;	
				//如果当前加载模块是要关注的模块
				if (MatchStr(pszCurLoadingFileName, (PCSTR)dwModuleName)) {
					DWORD dwModuleSize = GetModuleSize((DWORD_PTR)hModuleBase);
					MEMORY_BASIC_INFORMATION mbi = { 0 };
					if (dwModuleSize != 0 && VirtualQuery(hModuleBase, &mbi, sizeof(mbi)) != 0) {
						EnterCriticalSection(&g_CriSec);
						//在此赋值，模块基地址初始化为0，在此进行比较交换，在此进行赋值
						if (InterlockedCompareExchange((volatile ULONG*)&(g_Info.SystemDllInfo[i].dwModuleBase), (ULONG64)hModuleBase, 0) == 0) {
							DWORD dwNewProtect = mbi.Protect | PAGE_GUARD;
							DWORD dwSize = 0x1000;
							DWORD dwOldProtect = 0;
							PVOID BaseAddress = (PVOID)hModuleBase;
							PVOID PEAddress = (PVOID)(IMAGE_NT_HEADERS*)((BYTE*)hModuleBase + ((IMAGE_DOS_HEADER*)hModuleBase)->e_lfanew);
							g_Info.SystemDllInfo[i].dwEATAddr = GetModuleEAT((DWORD_PTR)hModuleBase);
							g_Info.SystemDllInfo[i].dwModuleSize = GetModuleSize((DWORD_PTR)hModuleBase);
							g_Info.SystemDllInfo[i].dwPageAddrOfEAT = g_Info.SystemDllInfo[i].dwEATAddr & 0xFFFF000;
							g_Info.SystemDllInfo[i].dwProtect = dwNewProtect;
							g_Info.SystemDllInfo[i].dwSize = dwSize;
							//为MZ头加上保护
							pNtProtectVirtualMemory(GetCurrentProcess(), &BaseAddress, &dwSize, dwNewProtect, &dwOldProtect);
							//为PE头加上保护
							pNtProtectVirtualMemory(GetCurrentProcess(), &PEAddress, &dwSize, dwNewProtect, &dwOldProtect);
						}
						LeaveCriticalSection(&g_CriSec);
					}
					return;
				}
			}
		}
	}
	return;
}


DWORD CheckStack(PEXCEPTION_POINTERS ExceptionInfo) {
	DWORD dwTEB = (DWORD)NtCurrentTeb();
	DWORD dwStackBase = *(DWORD*)(dwTEB + 4);//线程堆栈顶部
	DWORD dwStackLimit = *(DWORD*)(dwTEB + 8);//线程堆栈底部
	if (ExceptionInfo->ContextRecord->Esp < dwStackLimit ||
		ExceptionInfo->ContextRecord->Ebp > dwStackBase) {
		ErrorReport();
	}

	return 0;
}

BOOL ModuleInWhiteList(TCHAR* ModuleName)
{
	for (int i = 0; i < sizeof(__g_ModuleNames) / sizeof(__g_ModuleNames[0]); i++) {
		if (_tcscmp(__g_ModuleNames[i], ModuleName) == 0) {
			return TRUE;
		}
	}
	return FALSE;
}
