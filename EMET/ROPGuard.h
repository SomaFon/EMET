#pragma once
#include "Hook.h"

typedef enum _EXE_FLOW_TYPE
{
	EXE_FLOW_ERROR = 0,
	EXE_FLOW_BRANCH = 1,        //call����jmp��תָ��
	EXE_FLOW_SEQ = 2,        //˳��ִ��ָ��
	EXE_FLOW_RETURN = 3       //����ָ��
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
	CALL_INS,                  //CALLָ��
	JMP_INS,
	MOV_ESP_EBP_INS,
	PUSH_INS,                 //PUSHָ��
	POP_INS,                   //һ���POPָ��
	POP_ESP_INS,           //POP ESPָ��
	POP_EBP_INS,           //POP EBPָ��
	ADD_ESP_INS,          //ADD ESP,XXXָ��
	ADD_EBP_INS,          //ADD EBP,XXXָ��
	SUB_ESP_INS,           //SUB ESP,XXXָ��
	SUB_EBP_INS,           //SUB EBP,XXXָ��
	LEAVE_INS,               //LEAVEָ��
	RETURN_INS,            //RETURNָ��
}INSTURCTION_TYPE;


BOOL MemProt(UNION_HOOKEDFUNCINFO::PMEMPROT_INFO pMemProtStruct);
BOOL LoadLib(UNION_HOOKEDFUNCINFO::PLOADLIB_INFO pLoadLibInfo, PHOOKINFO pHookInfo);
BOOL StackPivot(DWORD dwRetAddr, DWORD dwOriginalAPIAddr, PHOOKINFO hookInfo);
BOOL Caller(DWORD dwRetAddess);
BOOL SimExecFlow(PHOOKINFO pHookInfo);
EXE_FLOW_TYPE SimulateExeFlow(SIMULATE_CONTEXT *SimulateContext);
INSTURCTION_TYPE GetInstructionType(char*szASM);
