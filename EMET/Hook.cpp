#include"Hook.h"
#include "EMET.h"
//��Ҫ����˳��
struct FUNCINFO g_HookedFuncInfo[] = {
	{"kernel32.LoadLibraryA", 1, 0x3D4CE},
	{"kernel32.LoadLibraryW", 1, 0x3D4CE},
	{"kernel32.LoadLibraryExA", 3, 0x3D4CE},
	{"kernel32.LoadLibraryExW", 3, 0x3D4CE},
	{"kernelbase.LoadLibraryExA", 3, 0x3D4CF},
	{"kernelbase.LoadLibraryExW", 3, 0x3D4CF},
	{"kernel32.LoadPackagedLibrary", 2, 0x14CE},
	{"ntdll.LdrLoadDll", 4, 0x14CF},
	{"kernel32.VirtualAlloc", 4, 0X14C2},
	{"kernel32.VirtualAllocEx", 5, 0X14C2},
	{"kernelbase.VirtualAlloc", 4, 0X14C3},
	{"kernelbase.VirtualAllocEx", 5, 0X14C3},
	{"ntdll.NtAllocateVirtualMemory", 6, 0X14C3},
	{"kernel32.VirtualProtect", 4, 0X14F2},
	{"kernel32.VirtualProtectEx", 5, 0X14F2},
	{"kernelbase.VirtualProtect", 4, 0X14F3},
	{"kernelbase.VirtualProtectEx", 5, 0X14F3},
	{"ntdll.NtProtectVirtualMemory", 5, 0X14F3},
	{"kernel32.HeapCreate", 3, 0X14C2},
	{"kernelbase.HeapCreate", 3, 0X14C3},
	{"ntdll.RtlCreateHeap", 6, 0X14C3},
	{"kernel32.CreateProcessA", 10, 0X14C2},
	{"kernel32.CreateProcessW", 10, 0X14C2},
	{"kernel32.CreateProcessInternalA", 12, 0X14C2},
	{"kernel32.CreateProcessInternalW", 12, 0X14C2},
	{"ntdll.NtCreateUserProcess", 11, 0x14C3},
	{"ntdll.NtCreateProcess", 8, 0X14C3},
	{"ntdll.NtCreateProcessEx", 9, 0X14C3},
	{"kernel32.CreateRemoteThread", 7, 0X14C2},
	{"kernel32.CreateRemoteThreadEx", 8, 0X14C2},
	{"kernelbase.CreateRemoteThreadEx", 8, 0X14C3},
	{"ntdll.NtCreateThreadEx", 11, 0X14C3},
	{"kernel32.WriteProcessMemory", 5, 0X14C2},
	{"kernelbase.WriteProcessMemory", 5, 0X14C3},
	{"ntdll.NtWriteVirtualMemory", 5, 0X14C3},
	{"kernel32.WinExec", 2, 0x14C2},
	{"kernel32.CreateFileA", 7, 0x14C2},
	{"kernel32.CreateFileW", 7, 0x14C2},
	{"kernelbase.CreateFileW", 7, 0x14C3},
	{"ntdll.NtCreateFile", 11, 0x14C3},
	{"kernel32.CreateFileMappingA", 6, 0x14C2},
	{"kernel32.CreateFileMappingW", 6, 0X14C2},
	{"kernelbase.CreateFileMappingW", 6, 0X14C3},
	{"kernelbase.CreateFileMappingNumaW", 7, 0X14C3},
	{"ntdll.NtCreateSection", 7, 0X14C3},
	{"kernel32.MapViewOfFile", 5, 0X14C2},
	{"kernel32.MapViewOfFileEx", 6, 0X14C2},
	{"kernelbase.MapViewOfFile", 5, 0X14C3},
	{"kernelbase.MapViewOfFileEx", 6, 0X14C3},
	{"kernel32.MapViewOfFileFromApp", 4, 0X14C3},
	{"ntdll.NtUnmapViewOfSection", 2, 0x300002},
	{"ntdll.NtMapViewOfSection", 10, 0x300002},
	{"ntdll.RtlAddVectoredExceptionHandler", 2, 2},
	{"kernel32.SetProcessDEPPolicy", 1, 0},
	{"kernel32.GetProcessDEPPolicy", 3, 0},
	{"ntdll.LdrHotPatchRoutine", 1, 0X102}
};
PGLOBALHOOKINFO g_HookedApiInfo = NULL;

BYTE g_HookShellCode[] = {
	0x68, 0x00, 0x00, 0x00, 0x00,   //push Api index
	0x68, 0x00, 0x00, 0x00, 0x00,   //push hookdispatcher
	0x68, 0x00, 0x00, 0x00, 0x00,   //push true Api addr
	0x68, 0x00, 0x00, 0x00, 0x00,   //push argc1
	0x53,  //push ebx
	0x60,  //pushad
	0x54,  //push esp
	0xE8, 0x00, 0x00, 0x00, 0x00,
	0x61,  //popad
	0x83, 0xC4, 0x14, //add esp,14
	0xC2, 0x00, 0x00  //ret argc*4
};


//Hook�����������ú���Ϊ��������
//�����к�������hook
//FakeFuc��Proxy_HookDispatcherPtr
void HookFunctions() {
	for (int i = 0; i < sizeof(g_HookedFuncInfo) / sizeof(g_HookedFuncInfo[0]); i++) {
		HookCurFunction(i);
	}
	return;
}
//hook�����ĺ������ú���Ϊ��������
void HookCurFunction(int nIndex) {
	DWORD dwOldProctect = 0;
	BYTE *pApiHeadCode = NULL;
	BYTE *pHookShellCode = NULL;
	FARPROC pProcAddress = NULL;
	HMODULE hModuleBase = NULL;
	FUNCINFO *pCurFuncInfo = NULL;
	char szASM[0x100] = { 0 };
	char pszFuncName[MAX_PATH] = {0};
	char pszModuleName[MAX_PATH] = { 0 };
	int nPathLen = 0;
	UINT uCodeSize = 0;
	int nHookedBytes = 0;
	DWORD dwDisAsmAddr = 0;

	//��ñ�Hook�����ĺ�������ģ����
	pCurFuncInfo = &g_HookedFuncInfo[nIndex];

	SplitStringForDllAndFunc(pCurFuncInfo->pszFuncPath, pszModuleName, pszFuncName);

	//���ģ�����ַ
	hModuleBase = GetModuleHandleA(pszModuleName);
	if (!hModuleBase) {
		return;
	}
	//��øú����ڸ�ģ��ĵ������ַ
	pProcAddress = GetProcAddress(hModuleBase, pszFuncName);
	if (!pProcAddress) {
		return;
	}

	//�����ú���ǰ����ֽڵ�ָ��
	dwDisAsmAddr = (DWORD)pProcAddress;
	do {
		//dwDisAsmAddr��������ָ��ĵ�ַ��szASM����Ž�����ķ������룬uCodeSize������ָ���
		Decode2Asm((PBYTE)dwDisAsmAddr, szASM, &uCodeSize, (UINT)dwDisAsmAddr);
		nHookedBytes += uCodeSize;
		dwDisAsmAddr += uCodeSize;
	} while (nHookedBytes < 5);

	/*���hookcode hookcode���ݣ�ԭ����ǰ����ֽ�ָ��+E9 offset��ת��ԭ��������ֽں�����ַ��*/
	pApiHeadCode = new BYTE[nHookedBytes + 5];
	pApiHeadCode[nHookedBytes] = 0xE9;
	//Offset = Ŀ�� - (Դ + 5)
	*(DWORD*)&pApiHeadCode[nHookedBytes + 1] = (DWORD)pProcAddress + nHookedBytes - (DWORD)(pApiHeadCode + nHookedBytes + 5);
	//���ԭ����ǰ����ֽ�ָ��
	memcpy(pApiHeadCode, pProcAddress, nHookedBytes);
	//ʹhookcode��ָ��Ϊ�ɶ���д��ִ��
	VirtualProtect(pApiHeadCode, nHookedBytes + 5, PAGE_EXECUTE_READWRITE, &dwOldProctect);

	/*
		���shellcode
		���ݣ�
		push API index
		push HookDispatcher
		push ԭ��������ָ���ַ��
		push ������������
		push ebx
		pushad
		push esp
		call Proxy_HookDispatcherPtr
		popad
		add esp 14
		ret argc*4
	*/
	pHookShellCode = new BYTE[sizeof(g_HookShellCode)];
	memcpy(pHookShellCode, g_HookShellCode, sizeof(g_HookShellCode));
	VirtualProtect(pHookShellCode, sizeof(g_HookShellCode), PAGE_EXECUTE_READWRITE, &dwOldProctect);
	*(DWORD*)&pHookShellCode[1] = nIndex;
	*(DWORD*)&pHookShellCode[6] = (DWORD)HookDispatcher;
	*(DWORD*)&pHookShellCode[11] = (DWORD)pApiHeadCode;
	*(DWORD*)&pHookShellCode[16] = pCurFuncInfo->nFuncArgc;
	*(DWORD*)&pHookShellCode[24] = (DWORD)Proxy_HookDispatcherPtr - (DWORD)&pHookShellCode[23 + 5];
	*(DWORD*)&pHookShellCode[33] = pCurFuncInfo->nFuncArgc * 4;

	//hookԭ���� ��ǰ����ֽڸ�Ϊ��תָ��E9 shellcode
	VirtualProtect(pProcAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProctect);
	*((BYTE*)pProcAddress) = 0xE9;
	*(DWORD*)((BYTE*)pProcAddress + 1) = (DWORD)pHookShellCode - ((DWORD)pProcAddress + 5);
	VirtualProtect(pProcAddress, 5, dwOldProctect, &dwOldProctect);

	g_HookedApiInfo[nIndex].dwApiIndex = nIndex;
	g_HookedApiInfo[nIndex].dwArgCount = pCurFuncInfo->nFuncArgc;
	g_HookedApiInfo[nIndex].dwTrueApiAddr = (DWORD)pApiHeadCode;
	g_HookedApiInfo[nIndex].dwOriginalApiAddr = (DWORD)pProcAddress;
	g_HookedApiInfo[nIndex].dwHookAddr = (DWORD)pHookShellCode;

}


//����ԭ����
DWORD Proxy_ApiCaller(int nApiArgCount, DWORD pApiArgv, DWORD pTrueApiAddr) {
	DWORD dwRet = 0;
	__asm {

		mov eax, nApiArgCount;
		mov ecx, eax;
		shl eax, 2;
		sub esp, eax;//���ݲ���������ջ

		mov edi, esp;
		mov esi, pApiArgv;//��ԭ�������������Ƶ�����ջ��
		rep movsd;

		mov eax, pTrueApiAddr;//��ת��ԭ������ַ��ִ��ԭ����
		call eax;
		mov dwRet, eax;
	}

	return dwRet;
}

//���壬����pHookDispatcher����
//�������Ϊ�ṹ��ָ��
void NTAPI Proxy_HookDispatcherPtr(PHOOKINFO hookInfo) {
	//���ԭ����������˵�һ�������ĵ�ַ
	hookInfo->dwArgAddr = (DWORD)&hookInfo->ApiArg;
	//����HookDispatcher��������ֵ������hookInfo->dwEax
	hookInfo->dwEax = ((HOOKDISPATCHER)hookInfo->pHookDispatcher)(hookInfo);
	return;
}

/*
	ret: �Ƿ���Ҫ�������
*/
BOOL InitializeFuncInfo(UNION_HOOKEDFUNCINFO::PUNKNOWN_INFO a1, int API_index, int API_argAddr) {

	DWORD dw2;
	DWORD dw3;
	BOOL bNextCheck = FALSE;

	switch (API_index)
	{
		//LoadLibraryA
	case 0:
		a1->dw3 = 0;
		goto LABEL_3;
	case 1:
		a1->dw3 = 1;
	LABEL_3:
		//LoadLibraryA PUNKNOWN_INFO��4 0 0 0 API_arg��һ������ LPCSTR  lpLibFileName
		//LoadLibraryW PUNKNOWN_INFO��4 0 0 1 API_arg��һ������ LPCWSTR lpLibFileName
		a1->dwType = 4;
		a1->dw1 = 0;
		a1->dw4 = *(DWORD *)API_argAddr;
		a1->dw2 = 0;
		bNextCheck = TRUE;
		break;

	case 2:
	case 4:
		a1->dw3 = 0;
		goto LABEL_6;
	case 3:
	case 5:
		a1->dw3 = 1;
	LABEL_6:
		//LoadLibraryEA PUNKNOWN_INFO��4 1 DWORD dwFlags 0 API_arg��һ������ LPCSTR lpLibFileName
		//LoadLibraryEW PUNKNOWN_INFO��4 1 DWORD dwFlags 1 API_arg��һ������ LPCWSTR lpLibFileName
		a1->dwType = 4;
		a1->dw1 = 1;
		a1->dw4 = *(DWORD *)API_argAddr;
		a1->dw2 = *(DWORD *)(API_argAddr + 8);
		bNextCheck = TRUE;
		break;
	case 8:
	case 10:
		//VirtualAlloc
		a1->dw4 = 0;
		a1->dwType = 1;
		a1->dw1 = *(DWORD *)API_argAddr;
		dw2 = *(DWORD *)(API_argAddr + 4);
		goto LABEL_11;
	case 9:
	case 11:
		//VirtualAllocEx
		a1->dwType = 1;
		a1->dw4 = *(DWORD *)API_argAddr;
		a1->dw1 = *(DWORD *)(API_argAddr + 4);
		a1->dw2 = *(DWORD *)(API_argAddr + 8);
		dw3 = *(DWORD *)(API_argAddr + 16);
		goto LABEL_9;
	case 12:
		//NtAllocateVirtualMemory
		a1->dwType = 1;
		a1->dw4 = *(DWORD *)API_argAddr;
		a1->dw1 = **(DWORD **)(API_argAddr + 4);
		a1->dw2 = **(DWORD **)(API_argAddr + 0xC);
		dw3 = *(DWORD *)(API_argAddr + 20);
		goto LABEL_9;
	case 13:
	case 15:
		//VirtualProtect
		a1->dw4 = 0;
		a1->dwType = 2;
		a1->dw1 = *(DWORD *)API_argAddr;
		a1->dw2 = *(DWORD *)(API_argAddr + 4);
		dw3 = *(DWORD *)(API_argAddr + 8);
		goto LABEL_9;
	case 14:
	case 16:
		//VirtualProtectEx
		a1->dwType = 2;
		a1->dw4 = *(DWORD *)API_argAddr;
		a1->dw1 = *(DWORD *)(API_argAddr + 4);
		dw2 = *(DWORD *)(API_argAddr + 8);
		goto LABEL_11;
	case 17:
		//NtProtectVirtualMemory
		a1->dwType = 2;
		a1->dw4 = *(DWORD *)API_argAddr;
		a1->dw1 = **(DWORD **)(API_argAddr + 4);
		dw2 = **(DWORD **)(API_argAddr + 8);
	LABEL_11:
		//VirtualAlloc  PUNKNOWN_INFO��1  LPVOID lpAddress  SIZE_T dwSize  DWORD flProtect  0
		//VirtualProtectEx  PUNKNOWN_INFO��2  LPVOID lpAddress  SIZE_T dwSize  DWORD flNewProtect  HANDLE hProcess
		a1->dw2 = dw2;
		dw3 = *(DWORD *)(API_argAddr + 12);
	LABEL_9:
		//VirtualAllocEx  PUNKNOWN_INFO��1  LPVOID lpAddress  SIZE_T dwSize  DWORD flProtect  HANDLE hProcess
		//NtAllocateVirtualMemory  PUNKNOWN_INFO��1  PVOID *BaseAddress  PSIZE_T RegionSize  ULONG Protect  HANDLE ProcessHandle
		//VirtualProtect  PUNKNOWN_INFO��2  LPVOID lpAddress  SIZE_T dwSize  DWORD flNewProtect  0
		//NtProtectVirtualMemory  PUNKNOWN_INFO��2  PVOID *BaseAddress  PULONG RegionSize  ULONG NewProtect  HANDLE ProcessHandle
		a1->dw3 = dw3;
		bNextCheck = TRUE;
		break;
	case 18:
	case 19:
		//HeapCreate  PUNKNOWN_INFO��3  DWORD flOptions
		a1->dwType = 3;
		a1->dw1 = *(DWORD *)API_argAddr;
		bNextCheck = TRUE;
		break;
	case 28:
	case 29:
	case 30:
		//CreateRemoteThread  
		//CreateRemoteThreadEx
		//6  HANDLE hProcess
		a1->dwType = 6;
		a1->dw1 = *(DWORD *)API_argAddr;
		bNextCheck = TRUE;
		break;
	case 31:
		//NtCreateThreadEx  HANDLE ProcessHandle
		a1->dwType = 6;
		a1->dw1 = *(DWORD *)(API_argAddr + 12);
		break;
	default:
		break;
	}
	

	//�ж��Ƿ���Ҫ�������
	if (a1->dwType > 0 && bNextCheck == TRUE) {
		if (a1->dwType == TYPE_MEMALLOC || a1->dwType == TYPE_MEMPROTECT) {
			//0xF0 = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
			return (((UNION_HOOKEDFUNCINFO::PMEMPROT_INFO)a1)->dwNewProtect & 0xF0) != 0;
		}

		if (a1->dwType == TYPE_HEAPCREATE) {
			//HeapCreate.flOptions == HEAP_CREATE_ENABLE_EXECUTE? 
			return (a1->dw1 >> 18) & 1;
		}
		if (a1->dwType == TYPE_THREADCREATE) {
			return a1->dw1 != (DWORD)GetCurrentProcess();
		}
	}

	return TRUE;
}
