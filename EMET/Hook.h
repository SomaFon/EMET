#pragma once
#include "Util.h"
#include "Disasm.h"
#include "Decode2Asm.h"


//已hook函数信息
union UNION_HOOKEDFUNCINFO
{
	typedef struct UNKNOWN_INFO {
		DWORD dwType;
		DWORD dw1;
		DWORD dw2;
		DWORD dw3;
		DWORD dw4;
		DWORD dw5;
	}UNKNOWN_INFO, *PUNKNOWN_INFO;


	typedef struct LOADLIB_INFO {
		DWORD dwType;
		DWORD dwIsExVersion;
		DWORD dwFlags;
		DWORD dwIsWideVersion;
		DWORD dwFileNamePtr;
		DWORD dw5;
	}LOADLIB_INFO, ASR_INFO, *PLOADLIB_INFO, *PASR_INFO;


	typedef struct MEMPROT_INFO {
		DWORD dwType;
		DWORD dwAddress;
		DWORD dwSize;
		DWORD dwNewProtect;
		DWORD dwProcess;
	}MEMPROT_INFO, EAFP_INFO, *PMEMPROT_INFO, *PEAFP_INFO;

};

//函数信息
typedef struct FUNCINFO {
	const char *pszFuncPath;//函数路径
	int nFuncArgc;//参数个数
	DWORD dwFuncMask;//函数掩码
}FUNCINFO, *PFUNCINFO;


typedef struct HOOKINFO {
	DWORD dwedi;
	DWORD dwesi;
	DWORD dwebp;
	DWORD dwesp;
	DWORD dwebx;
	DWORD dwedx;
	DWORD dwecx;
	DWORD dwEax;
	DWORD dwArgAddr;//push ebx 在Proxy_HookDispatcherPtr进行赋值，hookInfo->dwArgAddr = (DWORD)&hookInfo->ApiArg
	DWORD dwArgc;
	DWORD dwTrueApiAddr;
	DWORD pHookDispatcher;
	DWORD dwIndexApi;
	DWORD dwRetAddr;//call 原函数时push的eip
	DWORD ApiArg[1];//原函数push的最左端第一个参数所在地址，很巧妙地利用原函数对参数地push
}HOOKINFO, *PHOOKINFO;

typedef DWORD(__stdcall *HOOKDISPATCHER)(PHOOKINFO hookInfo);

void HookFunctions();
void HookCurFunction(int nIndex);
DWORD Proxy_ApiCaller(int nApiArgCount, DWORD pApiArgv, DWORD pTrueApiAddr);
void NTAPI Proxy_HookDispatcherPtr(PHOOKINFO hookInfo);
BOOL InitializeFuncInfo(UNION_HOOKEDFUNCINFO::PUNKNOWN_INFO a1, int API_index, int API_argAddr);
