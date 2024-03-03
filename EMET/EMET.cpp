#include "EMET.h"
#include <atlbase.h>
#include <oleacc.h>
#include <mshtml.h>

extern struct FUNCINFO g_HookedFuncInfo[56];
extern PGLOBALHOOKINFO g_HookedApiInfo;
extern NTPROTECTVIRTUALMEMORY pNtProtectVirtualMemory;


#define DLLMAX 13

REGINFO g_RegInfo[DLLMAX] = { 0 };

GLOBALINFO g_Info = { 0 };
CRITICAL_SECTION g_CriSec;
GLOBALINFOLOCK g_Infowithlock = { 0 };

BYTE g_CodeOriginalSEH[] = {
	0x8B, 0xFF, //mov edi,edi
	0x55, //push ebp
	0x8B, 0xEC, //mov ebp,esp
	0xFF, 0x75, 0x14,//push dword ptr[ebp + 14h]
	0xFF, 0x75, 0x10,//push dword ptr[ebp + 10h]
	0xFF, 0x75, 0x0C,//push dword ptr[ebp + 0Ch]
	0xFF, 0x75, 0x08 //push dword ptr[ebp + 8]
};


void InitializeEMET() {
	int nIndex = 0;

	//1.申请全局的要Hook的函数信息
	//全局Hook信息  g_hookedFuncInfo[0]："kernel32.LoadLibraryA", 1, 0x3D4CE
	g_HookedApiInfo = new GLOBALHOOKINFO[sizeof(g_HookedFuncInfo) / sizeof(g_HookedFuncInfo[0])];

	//2.对申请的全局Hook函数信息初始化

	//1）初始化KiUserExceptionDispatcher函数
	//init pNtdllKiUserExceptionDispatcher 获得KiUserExceptionDispatcher函数地址
	g_Info.pNtdllKiUserExceptionDispatcher = GetProcAddress(GetModuleHandle(_T("ntdll")), "KiUserExceptionDispatcher");


	//2）初始化HeapSprayAddrTable
	//init HeapSprayAddrTable 初始化堆喷地址表，将通常被攻击者用来分配恶意代码的内存区域预先分配了
	g_Info.HeapSprayAddrTable[nIndex++] = 0x0A040A04;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x0A0A0A0A;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x0B0B0B0B;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x0C0C0C0C;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x0D0D0D0D;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x0E0E0E0E;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x04040404;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x05050505;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x06060606;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x07070707;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x08080808;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x09090909;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x20202020;
	g_Info.HeapSprayAddrTable[nIndex++] = 0x14141414;


	//4）获得EMETdll模块的基地址和大小
	g_Info.dwBaseAddrEMET = (DWORD)GetModuleHandleA(NULL);
	g_Info.dwSizeEMET = GetModuleSize((DWORD_PTR)g_Info.dwBaseAddrEMET);


	//初始化EAF，这3个模块在EAF中赋值
	nIndex = 0;
	g_Info.SystemDllInfo_EAF = &g_Info.SystemDllInfo[nIndex];
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("ntdll.dll");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("kernelbase.dll");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("kernel32.dll");
	g_Info.SystemDllInfo_EAFPlus = &g_Info.SystemDllInfo[nIndex];//指向SystemDllInfo[4]
	//初始化EAF，这10个模块在EAFPlus中赋值
	//g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("EMET.exe");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("mshtml.dll");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("flash*.ocx");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("jscript*.ocx");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("vbscript.dll");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("vgx.dll");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("mozjs.dll");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("xul.dll");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("acrord32.dll");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("acrofx32.dll");
	g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)_T("acroform.dll");

	//init pszASRCheckedDllNameAry
	nIndex = 0;
	g_Info.pszASRCheckedDllNameAry[nIndex++] = "npjpi*.dll";
	g_Info.pszASRCheckedDllNameAry[nIndex++] = "jp2iexp.dll";
	g_Info.pszASRCheckedDllNameAry[nIndex++] = "vgx.dll";
	g_Info.pszASRCheckedDllNameAry[nIndex++] = "msxml4*.dll";
	g_Info.pszASRCheckedDllNameAry[nIndex++] = "wshom.ocx";
	g_Info.pszASRCheckedDllNameAry[nIndex++] = "scrrun.dll";
	g_Info.pszASRCheckedDllNameAry[nIndex++] = "vbscript.dll";

	InitializeCriticalSection(&g_CriSec);

	//注册VEH异常处理函数
	PVOID pVEH_EMET = AddVectoredExceptionHandler(0, VectoredHandler);
	if (pVEH_EMET != 0)
		EnterCriticalSection(&g_CriSec);
	g_Info.hVEH = pVEH_EMET;
	LeaveCriticalSection(&g_CriSec);

	//Hook目标函数
	HookFunctions();

}
void ApllyEMET()
{
	/*
	g_Info.ASR = TRUE;
	g_Info.BottomUpASLR = TRUE;
	g_Info.Caller = TRUE;
	g_Info.DEP = TRUE;
	g_Info.EAF = TRUE;
	g_Info.EAF_plus = TRUE;
	g_Info.HeapSpray = TRUE;
	g_Info.LoadLib = TRUE;
	g_Info.MandatoryASLR = TRUE;
	g_Info.MemProt = TRUE;
	g_Info.NullPage = TRUE;
	g_Info.SEHOP = TRUE;
	g_Info.SimExecFlow = TRUE;
	g_Info.StackPivot = TRUE;
	*/
	EnterCriticalSection(&g_CriSec);
	g_Info.ASR = TRUE;
	g_Info.BottomUpASLR = TRUE;
	g_Info.Caller = TRUE;
	g_Info.DEP = TRUE;
	g_Info.EAF = TRUE;
	g_Info.EAF_plus = TRUE;
	g_Info.HeapSpray = TRUE;
	g_Info.LoadLib = TRUE;
	g_Info.MandatoryASLR = TRUE;
	g_Info.MemProt = TRUE;
	g_Info.NullPage = TRUE;
	g_Info.SEHOP = TRUE;
	g_Info.SimExecFlow = TRUE;
	g_Info.StackPivot = TRUE;
	LeaveCriticalSection(&g_CriSec);

	EAF();



}


//执行两次原函数
DWORD HookDispatcher(PHOOKINFO pHookInfo) {

	DWORD dwIndexApi = pHookInfo->dwIndexApi;
	DWORD dwApiRet = 0;
	DWORD dwApiMask = g_HookedFuncInfo[dwIndexApi].dwFuncMask;

	//如果传入参数为空，直接调用原函数
	if (pHookInfo == NULL) {
		return Proxy_ApiCaller(pHookInfo->dwArgc, pHookInfo->dwArgAddr, pHookInfo->dwTrueApiAddr);
	}

	//如果Hook的是NtUnmapViewOfSection/NtMapViewOfSection，且开启了MandatoryASLR
	if (dwApiMask & 0x100000 && g_Info.MandatoryASLR) {
		return MandatoryASLR(pHookInfo);
	}

	UNION_HOOKEDFUNCINFO::UNKNOWN_INFO FuncInfo;
	//初始化函数信息
	if (InitializeFuncInfo(&FuncInfo, dwIndexApi, pHookInfo->dwArgAddr)) {

		if (dwApiMask & 0x40 && g_Info.StackPivot != 0) {
			StackPivot(pHookInfo->dwRetAddr, g_HookedApiInfo[pHookInfo->dwIndexApi].dwOriginalApiAddr, pHookInfo);
		}
		//VirtualProtect
		if (dwApiMask & 0x10 && g_Info.MemProt != 0) {
			MemProt((UNION_HOOKEDFUNCINFO::PMEMPROT_INFO)&FuncInfo);
		}

		if (dwApiMask & 0x400 && g_Info.Caller) {
			Caller(pHookInfo->dwRetAddr);
		}

		if (dwApiMask & 0x1000 && g_Info.SimExecFlow) {
			//SimExecFlow(pHookInfo);
		}
		//LoadLibrary
		if (dwApiMask & 4 && g_Info.LoadLib != 0) {
			LoadLib((UNION_HOOKEDFUNCINFO::PLOADLIB_INFO)&FuncInfo, pHookInfo);
		}
		//LoadLibrary
		if (dwApiMask & 0x4000 && g_Info.ASR != 0) {
			ASR((UNION_HOOKEDFUNCINFO::PASR_INFO)&FuncInfo);
		}
	}

	//执行原函数
	//Proxy_ApiCaller(pHookInfo->dwArgc, pHookInfo->dwArgAddr, pHookInfo->dwTrueApiAddr);

	EnterCriticalSection(&g_CriSec);
	dwApiRet = Proxy_ApiCaller(pHookInfo->dwArgc, pHookInfo->dwArgAddr, pHookInfo->dwTrueApiAddr);
	LeaveCriticalSection(&g_CriSec);

	//执行原函数。获得返回值

	if (dwApiMask & 0x10000 && g_Info.EAF_plus) {
		HMODULE hModule = (HMODULE)dwApiRet;
		EAF_PLUS((UNION_HOOKEDFUNCINFO::PEAFP_INFO)&FuncInfo, hModule);
	}

	return dwApiRet;
}






DWORD NullPage() {
	return proxy_NtAllocateVirtualMemory((PVOID)1, 0x1000);
}

DWORD HeapSpray() {
	DWORD dwRet = 0;

	for (int i = 0; i < 14; i++) {
		PVOID BaseAddress = (PVOID)g_Info.HeapSprayAddrTable[i];
		if (BaseAddress == 0) {
			break;
		}
		dwRet = proxy_NtAllocateVirtualMemory(BaseAddress, 0x1000);
	}

	return dwRet;
}



//异常处理函数
LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	PEXCEPTION_RECORD pExceptionRecord = pExceptionInfo->ExceptionRecord;
	DWORD dwExceptionCode = pExceptionRecord->ExceptionCode;
	DWORD dwExceptionAddress = (DWORD)pExceptionRecord->ExceptionAddress;
	//处理STATUS_GUARD_PAGE异常
	if (dwExceptionCode == STATUS_SINGLE_STEP || dwExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
		return EAF_Handler(pExceptionInfo);
	}

	if (dwExceptionCode == STATUS_ACCESS_VIOLATION && pExceptionRecord->NumberParameters == 2) {
		if (dwExceptionAddress - g_Info.dwBaseAddrEMET >= g_Info.dwSizeEMET) {

			if (g_Info.HeapSpray) {
				DWORD dwAccessedAddrPage = pExceptionRecord->ExceptionInformation[1] & 0xFFFF0000;
				for (int i = 0; i < 14; i++) {
					if (dwAccessedAddrPage == (g_Info.HeapSprayAddrTable[i] & 0xFFFFF000)) {
						if (CheckExceptAddrAndSEH(pExceptionRecord)) {
							return 0;
						}
						else {
							ErrorReport();
						}
					}
				}
			}

		}
	}
	return 0;
}

//PEXCEPTION_POINTERS：内核传给用户态的异常信息
LONG EAF_Handler(PEXCEPTION_POINTERS pExceptionInfo) {
	PCONTEXT pContextRecord = pExceptionInfo->ContextRecord;
	PEXCEPTION_RECORD pExceptionRecord = pExceptionInfo->ExceptionRecord;
	BOOL bAccessAddrInEATPage = FALSE;
	BOOL bAccessAddrInMZPage = FALSE;
	DWORD dwCurEsp = pContextRecord->Esp;
	DWORD dwCurEip = pContextRecord->Eip;
	HMODULE AttckModuleHandle, TargetModuleHandle;
	char AttackModuleName[MAX_PATH] = { 0 };
	char TargetModuleName[MAX_PATH] = { 0 };

	if (pExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
	{
		if (g_Info.EAF)
		{
			int nIndexDll = 0;
			DWORD dwEip = dwCurEip;
			ULONG_PTR uTargetAddress = pExceptionRecord->ExceptionInformation[1];//不可访问数据的虚拟地址

			//判断发生异常处的堆栈指针（EBP，ESP）和当前线程是否一致，不一致直接退出进程
			CheckStack(pExceptionInfo);
			if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)dwEip, &AttckModuleHandle))
			{
				if (!AttckModuleHandle)
				{
					ErrorReport();
				}
				else
				{
					GetModuleName(AttckModuleHandle, AttackModuleName);
					if (ModuleInWhiteList(AttackModuleName) == FALSE) {
						ErrorReport();
					}

				}
			}
			else
			{
				ErrorReport();
			}
			GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
				GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				(LPCTSTR)uTargetAddress, &TargetModuleHandle);
			GetModuleName(TargetModuleHandle, TargetModuleName);

			for (nIndexDll = 0; nIndexDll < 13; nIndexDll++)
			{
				if (strcmp((const char *)(g_Info.SystemDllInfo[nIndexDll].dwModuleName), TargetModuleName) == 0)
				{
					g_Info.SystemDllInfo[nIndexDll].dwNoGuard = 1;
					break;
				}
					
			}

			//如果发生异常处地址在整个模块内，设置该模块的寄存器信息
			if (g_Info.SystemDllInfo[nIndexDll].dwNoGuard)
			{
  				pContextRecord->EFlags |= 0x100;
			}
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if (g_Info.EAF == 0 || pExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP) {
		return EXCEPTION_CONTINUE_SEARCH;
	}


	//在处理白名单模块对EAT的访问后，设置EFlag的TF标志位，触发单步异常，在这里重新设置PAGE_GUARD
	for (int i = 0; i < 13; i++) 
	{
		if (g_Info.SystemDllInfo[i].dwNoGuard)
		{
			if (g_Info.EAF)
			{
				g_Info.SystemDllInfo[i].dwNoGuard = 0;
				SIZE_T ProtectSize = 0x1000;
				PVOID pProtectEATAddr;
				PVOID pProtectMZAddr;
				PVOID pProtectPEAddr;
				DWORD OldProtect = 0;
				if (i < 3)
				{
					pProtectEATAddr = (PVOID)g_Info.SystemDllInfo[i].dwPageAddrOfEAT;
					pNtProtectVirtualMemory(GetCurrentProcess(), &pProtectEATAddr, &ProtectSize, 
						g_Info.SystemDllInfo[i].dwProtect, &OldProtect);
				}
				else
				{
					pProtectMZAddr = (PVOID)g_Info.SystemDllInfo[i].dwModuleBase;
					pProtectPEAddr = (PVOID)(IMAGE_NT_HEADERS*)((BYTE*)g_Info.SystemDllInfo[i].dwModuleBase + 
						((IMAGE_DOS_HEADER*)g_Info.SystemDllInfo[i].dwModuleBase)->e_lfanew);
					pNtProtectVirtualMemory(GetCurrentProcess(), &pProtectMZAddr, &ProtectSize,
						g_Info.SystemDllInfo[i].dwProtect, &OldProtect);
					pNtProtectVirtualMemory(GetCurrentProcess(), &pProtectPEAddr, &ProtectSize, 
						g_Info.SystemDllInfo[i].dwProtect, &OldProtect);

				}
				return EXCEPTION_CONTINUE_EXECUTION;

			}
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}




BOOL CheckDLLInBlackList(PCSTR pszDllName) {
	BOOL bLoadValid = TRUE;

	for (int i = 0; i < sizeof(g_Info.pszASRCheckedDllNameAry) / sizeof(g_Info.pszASRCheckedDllNameAry[0]); i++) {
		if (MatchStr(pszDllName, g_Info.pszASRCheckedDllNameAry[i]) == TRUE) {
			//match    
			bLoadValid = FALSE;
			break;
		}
	}

	if (bLoadValid == FALSE) {
		//若当前调用线程是GUI线程，
		if (IsGUIThread(0) == TRUE) {
			DWORD dwZone = CheckURLZone();
			/*
				Enum：URLZONE
				EMET的实现中，可以为每个被保护的程序设置不同的排除检测Internet空间
				如IE（排除检测两个空间：本地Intetnet和可信站点），
				
			*/
			bLoadValid = (dwZone == URLZONE_INTRANET || dwZone == URLZONE_TRUSTED);
		}
	}

	return bLoadValid;
}

BOOL ASR(UNION_HOOKEDFUNCINFO::PASR_INFO pStrucASR) {
	char *pszDllName_alloc = NULL;
	char *pszDllName = NULL;

	if (pStrucASR->dwType != 4 ||
		(pStrucASR->dwIsExVersion != FALSE && pStrucASR->dwFlags & LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_DATAFILE))
	{
		return TRUE;
	}

	if (pStrucASR->dwIsWideVersion) {
		int nDLLnameLen = wcslen((const wchar_t *)pStrucASR->dwFileNamePtr);
		pszDllName_alloc = new char[wcslen((const wchar_t *)pStrucASR->dwFileNamePtr) + 1];
		WideCharToMultiByte(CP_ACP, 0, (LPCWCH)pStrucASR->dwFileNamePtr, -1, pszDllName_alloc, nDLLnameLen, NULL, NULL);
		pszDllName = pszDllName_alloc;
	}
	else {
		pszDllName = (char*)pStrucASR->dwFileNamePtr;
	}

	if (CheckDLLInBlackList(pszDllName) == FALSE) {
		ErrorReport();
	}

	if (pszDllName_alloc != NULL) {
		delete[] pszDllName_alloc;
	}

	return TRUE;
}

BOOL CheckExceptAddrAndSEH(PEXCEPTION_RECORD pExceptionRecord) {
	PVOID ExceptionAddress = pExceptionRecord->ExceptionAddress;
	_EXCEPTION_REGISTRATION_RECORD *seh = (_EXCEPTION_REGISTRATION_RECORD *)__readfsdword(0);
	_NT_TIB *tib = (_NT_TIB*)NtCurrentTeb();
	if (seh >= tib->StackLimit || seh < tib->StackBase) {

		//find
		//GdiPlus!GdipCreateSolidFill: 8A 09        mov     cl,byte ptr [ecx]
		//                             FF 45 ??     inc     dword ptr[xxxxxx]
		if (ExceptionAddress && *(DWORD*)ExceptionAddress == 0x45FF098A) {
			PEXCEPTION_ROUTINE pFirstHandler = seh->Handler;
			if (seh->Next >= tib->StackLimit || seh->Next < tib->StackBase) {
				if (pFirstHandler) {
					if (proxy_GetModuleHandleEx((LPCTSTR)ExceptionAddress) == proxy_GetModuleHandleEx((LPCTSTR)pFirstHandler)) {
						if (memcmp(pFirstHandler, &g_CodeOriginalSEH, 0x12) == 0) {
							return 1;
						}
					}
				}
			}
		}
	}
	return 0;
}
