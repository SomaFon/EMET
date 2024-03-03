#pragma once
#include"EMET.h"


DWORD EAF();
void EAF_PLUS(UNION_HOOKEDFUNCINFO::PEAFP_INFO pMemProt, HMODULE hModuleBase);
DWORD CheckStack(PEXCEPTION_POINTERS ExceptionInfo);
BOOL ModuleInWhiteList(TCHAR* ModuleName);