#include"ROPGuard.h"

#define CALL_TYPE 6
DWORD g_CallInstructionLen[CALL_TYPE] = { 6, 5, 2, 3, 7, 4 };


BOOL StackPivot(DWORD dwRetAddr, DWORD dwOriginalAPIAddr, PHOOKINFO hookInfo) {
	PNT_TIB pTib = (PNT_TIB)NtCurrentTeb();
	DWORD dwStackLimit = (DWORD)pTib->StackLimit;
	DWORD dwStackBase = (DWORD)pTib->StackBase;

	if (hookInfo->dwArgAddr > dwStackBase || hookInfo->dwArgAddr < dwStackLimit) {
		ErrorReport();
	}

	return TRUE;
}

//�������ͼ�޸��ڴ�ҳ���Եĺ���
BOOL MemProt(UNION_HOOKEDFUNCINFO::PMEMPROT_INFO pMemProtStruct) {
	if (pMemProtStruct->dwType != 2) {
		return TRUE;
	}
	if (!(pMemProtStruct->dwNewProtect & 0xF0)) {
		return TRUE;
	}
	if (pMemProtStruct->dwProcess) {
		if (GetCurrentProcessId() != GetProcessId((HANDLE)pMemProtStruct->dwProcess)) {
			return TRUE;
		}
	}
	DWORD dwAddr = pMemProtStruct->dwAddress;
	DWORD teb = (DWORD)NtCurrentTeb();
	DWORD dwStackLimit = *(DWORD*)(teb + 8);
	DWORD dwStackBase = *(DWORD*)(teb + 4);
	if (((dwAddr + pMemProtStruct->dwSize + 0xFFF) & 0xFFFFF000) <= dwStackLimit
		|| (dwAddr & 0xFFFFF000) >= dwStackBase)
	{
		return TRUE;
	}
	ErrorReport();
}


BOOL Caller(DWORD dwRetAddess) {
	for (int i = 0; i < CALL_TYPE; i++) {
		DWORD dwCallLen = g_CallInstructionLen[i];
		DWORD dwDisAsmAddr = dwRetAddess - dwCallLen;
		UINT uCodeSize = 0;
		char szASM[0x100] = { 0 };
		Decode2Asm((PBYTE)dwDisAsmAddr, szASM, &uCodeSize, (UINT)dwDisAsmAddr);

		if (strstr(szASM, "call") != NULL) {
			return TRUE;

		}
	}
	//ָ���call
	ErrorReport();
	return FALSE;
}

BOOL SimExecFlow(PHOOKINFO pHookInfo) {
	SIMULATE_CONTEXT SimulateContext;
	SimulateContext.EBP = pHookInfo->dwRetAddr;
	SimulateContext.EIP = pHookInfo->dwRetAddr;
	SimulateContext.ESP = pHookInfo->dwArgAddr + pHookInfo->dwArgc * 4;
	for (int i = 0; i < 15; i++)
	{
		EXE_FLOW_TYPE FlowType = SimulateExeFlow(&SimulateContext);
		if (EXE_FLOW_ERROR == FlowType || EXE_FLOW_BRANCH == FlowType)
		{
			//���ģ��ִ�е�����תָ����ߺ���SimulateExeFlow����ִ�д����򷵻�TRUE
			return TRUE;
		}
		else if (EXE_FLOW_RETURN == FlowType)
		{
			//���ģ��ִ�е���ret/ret nָ�����Ҫ�Է��ص�ַ����Ч�Խ��м��飬������Ҫ���ж�
			//���ص�ַ��ǰһ��ָ���Ƿ�Ϊcallָ��
			//�����ﻹ�����жϸõ�ַ�Ƿ����ִ��
			if (FALSE == Caller(SimulateContext.EIP) || FALSE == IsExecutableAddress((LPVOID)SimulateContext.EIP))
			{
				return FALSE;
			}
		}
	}
	return TRUE;
}

EXE_FLOW_TYPE SimulateExeFlow(SIMULATE_CONTEXT *SimulateContext)
{
	EXE_FLOW_TYPE FlowType = EXE_FLOW_SEQ;

	DWORD dwDisAsmAddr = SimulateContext->EIP;
	UINT uCodeSize = 0;

	char szASM[0x100] = { 0 };
	Decode2Asm((PBYTE)dwDisAsmAddr, szASM, &uCodeSize, (UINT)dwDisAsmAddr);
	INSTURCTION_TYPE InstructionType = GetInstructionType(szASM);

	switch (InstructionType)
	{
	case ERROR_INS:
		//�������ʧ��
		FlowType = EXE_FLOW_ERROR;
		break;
	case CALL_INS:
	case JMP_INS:
		FlowType = EXE_FLOW_BRANCH;
		break;

	case MOV_ESP_EBP_INS:
		SimulateContext->ESP = SimulateContext->EBP;
		break;
	case PUSH_INS:
		SimulateContext->ESP = SimulateContext->ESP - 4;
		break;
	case POP_INS:
		SimulateContext->ESP = SimulateContext->ESP + 4;
		break;
	case POP_EBP_INS:
		SimulateContext->EBP = SimulateContext->ESP;
		SimulateContext->ESP = SimulateContext->ESP + 4;
		break;
	case POP_ESP_INS:
		SimulateContext->ESP = SimulateContext->ESP;
		SimulateContext->ESP = SimulateContext->ESP + 4;    //�˴�ֵ����ȶ����˵POP ESP֮�������ٶ��µ� 
															//ESP���е�����EMET�Ĵ�����ȷʵ����ô����-_-����
		break;
	case LEAVE_INS:
		SimulateContext->ESP = SimulateContext->EBP;
		SimulateContext->EBP = SimulateContext->ESP;
		SimulateContext->ESP = SimulateContext->ESP + 4;
		break;
	case RETURN_INS:
		FlowType = EXE_FLOW_RETURN;
		dwDisAsmAddr = SimulateContext->ESP;
		SimulateContext->ESP = SimulateContext->ESP + 4;
		break;
	}

	//����ָ�����ͣ��޸�EIP
	if (EXE_FLOW_SEQ == FlowType)
	{
		//���˳��ִ�У���ô��һ��ָ���ַ��Ϊ��ǰEIP����ָ���
		SimulateContext->EIP = SimulateContext->EIP + uCodeSize;
	}
	else if (EXE_FLOW_RETURN == FlowType)
	{
		//����Ƿ���ָ���ôEIP����Ϊ���ص�ַ
		SimulateContext->EIP = dwDisAsmAddr;
	}
	return FlowType;
}

INSTURCTION_TYPE GetInstructionType(char*szASM)
{
	INSTURCTION_TYPE InstructionType;
	if (strstr(szASM, "Illegal"))
	{
		InstructionType = ERROR_INS;;
	}
	else if (strstr(szASM, "call") != NULL)
	{
		InstructionType = CALL_INS;
	}
	else if (strstr(szASM, "jmp") != NULL)
	{
		InstructionType = JMP_INS;
	}
	else if (strstr(szASM, "mov esp,ebp") != NULL)
	{
		InstructionType = MOV_ESP_EBP_INS;
	}
	else if (strstr(szASM, "push") != NULL)
	{
		InstructionType = PUSH_INS;
	}
	else if (strstr(szASM, "pop") != NULL)
	{
		InstructionType = POP_INS;
	}
	else if (strstr(szASM, "pop esp") != NULL)
	{
		InstructionType = POP_ESP_INS;
	}
	else if (strstr(szASM, "pop ebp") != NULL)
	{
		InstructionType = POP_EBP_INS;
	}
	else if (strstr(szASM, "add esp") != NULL)
	{
		InstructionType = ADD_ESP_INS;
	}
	else if (strstr(szASM, "add ebp") != NULL)
	{
		InstructionType = ADD_EBP_INS;
	}
	else if (strstr(szASM, "sub esp") != NULL)
	{
		InstructionType = SUB_ESP_INS;
	}
	else if (strstr(szASM, "sub ebp") != NULL)
	{
		InstructionType = SUB_EBP_INS;
	}
	else if (strstr(szASM, "leave") != NULL)
	{
		InstructionType = LEAVE_INS;
	}
	else if (strstr(szASM, "ret") != NULL)
	{
		InstructionType = RETURN_INS;
	}
	return InstructionType;
}

BOOL LoadLib(UNION_HOOKEDFUNCINFO::PLOADLIB_INFO pLoadLibInfo, PHOOKINFO pHookInfo) {
	char *pszDllName_alloc = NULL;
	char *pszDllName = NULL;

	//��������ģ��ֻ��Ϊ�����ļ�����Դ�ļ�ʱ����������
	if (pLoadLibInfo->dwFlags != TYPE_LIBLOAD ||
		(pLoadLibInfo->dwIsExVersion == TRUE && pLoadLibInfo->dwFlags & LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE))
	{
		return TRUE;
	}
	//����ǿ��ֽڰ汾
	if (pLoadLibInfo->dwIsWideVersion == TRUE) {

		int nDLLnameLen = wcslen((const wchar_t *)pLoadLibInfo->dwFileNamePtr);
		pszDllName_alloc = new char[wcslen((const wchar_t *)pLoadLibInfo->dwFileNamePtr) + 1];
		WideCharToMultiByte(CP_ACP, 0, (LPCWCH)pLoadLibInfo->dwFileNamePtr, -1, pszDllName_alloc, nDLLnameLen, NULL, NULL);
		pszDllName = pszDllName_alloc;
	}
	else
	{
		pszDllName = (char*)pLoadLibInfo->dwFileNamePtr;
	}
	if (pszDllName) {

		BOOL bRet = IsUNCPath(pszDllName);
		if (bRet) {
			if (GetFileAttributesA((LPCSTR)pLoadLibInfo->dwFileNamePtr) != INVALID_FILE_ATTRIBUTES) {
				ErrorReport();
			}
		}
	}
	if (pszDllName_alloc != NULL) {
		delete[] pszDllName_alloc;
	}


	return TRUE;
}
