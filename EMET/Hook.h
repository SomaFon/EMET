#pragma once
#include "Util.h"
#include "Disasm.h"
#include "Decode2Asm.h"


//��hook������Ϣ
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

//������Ϣ
typedef struct FUNCINFO {
	const char *pszFuncPath;//����·��
	int nFuncArgc;//��������
	DWORD dwFuncMask;//��������
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
	DWORD dwArgAddr;//push ebx ��Proxy_HookDispatcherPtr���и�ֵ��hookInfo->dwArgAddr = (DWORD)&hookInfo->ApiArg
	DWORD dwArgc;
	DWORD dwTrueApiAddr;
	DWORD pHookDispatcher;
	DWORD dwIndexApi;
	DWORD dwRetAddr;//call ԭ����ʱpush��eip
	DWORD ApiArg[1];//ԭ����push������˵�һ���������ڵ�ַ�������������ԭ�����Բ�����push
}HOOKINFO, *PHOOKINFO;

typedef DWORD(__stdcall *HOOKDISPATCHER)(PHOOKINFO hookInfo);

void HookFunctions();
void HookCurFunction(int nIndex);
DWORD Proxy_ApiCaller(int nApiArgCount, DWORD pApiArgv, DWORD pTrueApiAddr);
void NTAPI Proxy_HookDispatcherPtr(PHOOKINFO hookInfo);
BOOL InitializeFuncInfo(UNION_HOOKEDFUNCINFO::PUNKNOWN_INFO a1, int API_index, int API_argAddr);
