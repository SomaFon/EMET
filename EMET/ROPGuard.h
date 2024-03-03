#pragma once
#include "Hook.h"

typedef enum _EXE_FLOW_TYPE
{
	EXE_FLOW_ERROR = 0,
	EXE_FLOW_BRANCH = 1,        //call或者jmp跳转指令
	EXE_FLOW_SEQ = 2,        //顺序执行指令
	EXE_FLOW_RETURN = 3       //返回指令
}EXE_FLOW_TYPE;
typedef struct _SIMULATE_CONTEXT
{
	DWORD UNKONWN;
	DWORD EBP;
	DWORD ESP;
	DWORD EIP;
}SIMULATE_CONTEXT;
typedef enum _INSTRUCTION_TYPE
{
	ERROR_INS = 0,
	CALL_INS,                  //CALL指令
	JMP_INS,
	MOV_ESP_EBP_INS,
	PUSH_INS,                 //PUSH指令
	POP_INS,                   //一般的POP指令
	POP_ESP_INS,           //POP ESP指令
	POP_EBP_INS,           //POP EBP指令
	ADD_ESP_INS,          //ADD ESP,XXX指令
	ADD_EBP_INS,          //ADD EBP,XXX指令
	SUB_ESP_INS,           //SUB ESP,XXX指令
	SUB_EBP_INS,           //SUB EBP,XXX指令
	LEAVE_INS,               //LEAVE指令
	RETURN_INS,            //RETURN指令
}INSTURCTION_TYPE;


BOOL MemProt(UNION_HOOKEDFUNCINFO::PMEMPROT_INFO pMemProtStruct);
BOOL LoadLib(UNION_HOOKEDFUNCINFO::PLOADLIB_INFO pLoadLibInfo, PHOOKINFO pHookInfo);
BOOL StackPivot(DWORD dwRetAddr, DWORD dwOriginalAPIAddr, PHOOKINFO hookInfo);
BOOL Caller(DWORD dwRetAddess);
BOOL SimExecFlow(PHOOKINFO pHookInfo);
EXE_FLOW_TYPE SimulateExeFlow(SIMULATE_CONTEXT *SimulateContext);
INSTURCTION_TYPE GetInstructionType(char*szASM);
