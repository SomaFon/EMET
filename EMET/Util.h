#pragma once
#include <iostream>
#include <tchar.h>
#include <windows.h>
#include <Windows.h>
#include <string>

using namespace std;

#ifdef _UNICODE
#define tstrchr wcsrchr
#else
#define tstrchr strrchr
#endif

#define PE32 0x10B
#define PE64 0x20B


typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef struct DLL_BASE_SIZE {
	DWORD dwBase;
	DWORD dwSize;
	DWORD dwProt;
	DWORD dwDllName;
}DLL_BASE_SIZE, *PDLL_BASE_SIZE;


typedef struct MODULEINFO {
	DWORD dwModuleBase;
	DWORD dwModuleSize;
	DWORD dwProtect;
	DWORD dwModuleName;
	DWORD dwPageAddrOfEAT;//EAT页地址
	DWORD dwEATAddr;//EAT地址
	DWORD dwSize;//EAF保护大小
	DWORD dwNoGuard;
}MODULEINFO, *PMODULEINFO;



//全局信息
typedef struct GLOBALINFO {
	DWORD dwExceptionReg; //异常寄存器
	BYTE DEP;//
	BYTE SEHOP;
	BYTE MandatoryASLR;
	BYTE NullPage;
	BYTE HeapSpray;
	BYTE EAF;
	BYTE EAF_plus;
	BYTE BottomUpASLR;
	BYTE ASR;
	//BYTE AntiDetours;
	//BYTE DeepHooks;
	//BYTE BannedFunctions;
	BYTE Caller;
	BYTE SimExecFlow;
	BYTE MemProt;
	BYTE LoadLib;
	BYTE StackPivot;
	PVOID pNtdllKiUserExceptionDispatcher;
	DWORD HeapSprayAddrTable[14];
	DWORD dwBaseAddrEMET;
	DWORD dwSizeEMET;
	PCSTR pszASRCheckedDllNameAry[20];
	HANDLE hVEH;
	MODULEINFO SystemDllInfo[13];//缺少赋值，推测为在InitEMET中赋值
	PMODULEINFO SystemDllInfo_EAF;//指向SystemDllInfo[0]
	PMODULEINFO SystemDllInfo_EAFPlus;//指向SystemDllInfo[4]
}GLOBALINFO, *PGLOBALINFO;

typedef struct GLOBALINFOLOCK {
	CRITICAL_SECTION CriSec;
	PGLOBALINFO info;
	DWORD dwPageSize;
	DWORD dwRefCount;
}GLOBALINFOLOCK, *PGLOBALINFOLOCK;


enum HOOK_FUNC_TYPE {
	TYPE_MEMALLOC = 1,//内存申请
	TYPE_MEMPROTECT,//VirtualProtect
	TYPE_HEAPCREATE,//堆申请
	TYPE_LIBLOAD,//加载模块函数
	TYPE_STACKPIVOT,//验证对战平衡性
	TYPE_THREADCREATE//创建线程
};




typedef struct _REGINGO {
	DWORD dwEsp_Guard_;
	DWORD dwEip_Guard;
	DWORD dwEsp1_Recover;
	DWORD dwEip1_Recover;
	DWORD dwEsp_Guard;
	DWORD dwEip_LastGuard;
	DWORD dwEsp1_LastRecover;
	DWORD dwEip1_LastRecover;
}REGINFO, *PREGINFO;


//全局Hook信息
typedef struct GLOBALHOOKINFO {
	DWORD dwOriginalApiAddr;//原函数地址
	DWORD dwHookAddr;//hook函数的地址
	DWORD dwTrueApiAddr;//真正函数的地址
	DWORD dwApiIndex;//API的索引
	DWORD dwArgCount;//参数个数
}GLOBALHOOKINFO, *PGLOBALHOOKINFO;

typedef DWORD(NTAPI *NTUNMAPVIEWOFSECTION)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress
	);



typedef
DWORD(NTAPI *NTALLOCATEVIRTUALMEMORY)(
	_In_ HANDLE ProcessHandle,
	_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
	);

typedef
DWORD(NTAPI *NTMAPVIEWOFSECTION)(
	_In_ HANDLE SectionHandle,
	_In_ HANDLE ProcessHandle,
	_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset,
	_Inout_ PSIZE_T ViewSize,
	_In_ SECTION_INHERIT InheritDisposition,
	_In_ ULONG AllocationType,
	_In_ ULONG Win32Protect
	);

typedef
ULONG(NTAPI *RTLRANDOM)(
	_Inout_ PULONG Seed
	);

typedef
DWORD(NTAPI *NTPROTECTVIRTUALMEMORY)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
	);

typedef HRESULT(__stdcall *OBJECTFROMLRESULT)(LRESULT lResult, REFIID riid, WPARAM wParam, void **ppvObject);



DWORD GetModuleEAT(DWORD_PTR ModuleBase);
DWORD GetModuleIAT(DWORD_PTR ModuleBase);
void GetModuleName(HANDLE ModuleHandle, TCHAR *ModuleName);
DWORD GetModuleSize(DWORD_PTR ModuleBase);
BOOL MatchStr(PCSTR pszDllName, PCSTR pszDllFormat);
void SplitStringForDllAndFunc(const char *pszPath, char *pszDllName, char *pszFuncName);
BOOL IsUNCPath(LPCSTR pszPath);
BOOL IsReloadNeeded(DWORD_PTR ModuleBase);
BOOL IsExecutableAddress(LPVOID VirtualAddress);

DWORD ErrorReport();

HMODULE proxy_GetModuleHandleEx(LPCTSTR lpModuleName);
DWORD proxy_NtAllocateVirtualMemory(PVOID BaseAddr_, SIZE_T RegionSize_);

