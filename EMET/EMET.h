#pragma once
#include "Hook.h"
#include "ASR.h"
#include "ASLR.h"
#include "EAF.h"
#include "ROPGuard.h"

void InitializeEMET();
void ApllyEMET();

void  HookFunctions();
DWORD HookDispatcher(PHOOKINFO hookInfo);

DWORD NullPage();
DWORD HeapSpray();



LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);
LONG EAF_Handler(PEXCEPTION_POINTERS pExceptionInfo);



BOOL ASR(UNION_HOOKEDFUNCINFO::PASR_INFO pStrucASR);
BOOL CheckExceptAddrAndSEH(PEXCEPTION_RECORD pExceptionRecord);
#pragma once
