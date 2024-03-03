#include "Util.h"
#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

DWORD GetModuleEAT(DWORD_PTR ModuleBase)
{
	IMAGE_DOS_HEADER* ImageDosHeader = NULL;
	IMAGE_OPTIONAL_HEADER*  ImageOptionalHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory;
	PULONG  AddressOfFunctions;
	ImageDosHeader = (IMAGE_DOS_HEADER *)ModuleBase;
	ImageOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((BYTE*)ModuleBase + ImageDosHeader->e_lfanew + 24);
	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ModuleBase + ImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	AddressOfFunctions = (ULONG*)((BYTE*)ModuleBase + ImageExportDirectory->AddressOfFunctions);
	return (DWORD)AddressOfFunctions;
}

DWORD GetModuleIAT(DWORD_PTR ModuleBase)
{
	IMAGE_DOS_HEADER* ImageDosHeader = NULL;
	IMAGE_OPTIONAL_HEADER*  ImageOptionalHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory;
	ImageDosHeader = (IMAGE_DOS_HEADER *)ModuleBase;
	ImageOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((BYTE*)ModuleBase + ImageDosHeader->e_lfanew + 24);
	IMAGE_IMPORT_DESCRIPTOR* ImageImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((PUINT8)ModuleBase
		+ ImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	return (DWORD)(ImageImportDescriptor->FirstThunk + ModuleBase);
}

void GetModuleName(HANDLE ModuleHandle, TCHAR *ModuleName)
{
	TCHAR ModulePath[MAX_PATH] = { 0 };
	TCHAR *tmpModuleName;
	if (GetModuleFileName((HMODULE)ModuleHandle, ModulePath, ARRAYSIZE(ModulePath)))
	{
		//截断模块名称
		TCHAR* p = tstrchr(ModulePath, _T('\\'));
		if (p)
		{
			p++;
			tmpModuleName = ModuleName;
			while (*p != '\0') {
				*tmpModuleName = *p;
				tmpModuleName++;
				p++;
			}
		}
	}
}

DWORD GetModuleSize(DWORD_PTR ModuleBase) {
	IMAGE_DOS_HEADER* ImageDosHeader = NULL;
	IMAGE_OPTIONAL_HEADER*  ImageOptionalHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory;
	ImageDosHeader = (IMAGE_DOS_HEADER *)ModuleBase;
	ImageOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((BYTE*)ModuleBase + ImageDosHeader->e_lfanew + 24);
	if (ImageOptionalHeader->Magic != PE32 && ImageOptionalHeader->Magic != PE64) {
		return 0;
	}
	return ImageOptionalHeader->SizeOfImage;
}


BOOL IsReloadNeeded(DWORD_PTR ModuleBase) {
	IMAGE_DOS_HEADER* ImageDosHeader = NULL;
	IMAGE_OPTIONAL_HEADER*  ImageOptionalHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory;
	ImageDosHeader = (IMAGE_DOS_HEADER *)ModuleBase;
	ImageOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((BYTE*)ModuleBase + ImageDosHeader->e_lfanew + 24);
	
	WORD wDllCharacteristics = 0;
	DWORD dwImageBase = 0;
	if (ImageOptionalHeader->Magic == PE32) {
		wDllCharacteristics = ImageOptionalHeader->DllCharacteristics;
		dwImageBase = ImageOptionalHeader->ImageBase;
	}
	else {
		if (ImageOptionalHeader->Magic != PE64) {
			return 0;
		}
		wDllCharacteristics = ImageOptionalHeader->DllCharacteristics;
		dwImageBase = ImageOptionalHeader->ImageBase;
	}
	//如果具有IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE标志，代表该PE文件已开启ASLR机制
	if ((wDllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0 && (DWORD)ModuleBase == dwImageBase) {
		return FALSE;
	}
	
	return TRUE;
}


BOOL MatchStr(PCSTR pszDllName, PCSTR pszDllFormat) {
	if (pszDllName && pszDllFormat) {
		char cFormatStr = *pszDllFormat;
		if (cFormatStr != '*' || pszDllFormat[1] != 0) {
			char cDllName = *pszDllName;
			if (cDllName == 0) {
				return cFormatStr == 0;
			}

			if (cFormatStr != '*') {
				if (cFormatStr != '?') {
					if (cFormatStr != cDllName) {
						return FALSE;
					}
				}
				return MatchStr(pszDllName + 1, pszDllFormat + 1);
			}

			if (MatchStr(pszDllName, pszDllFormat + 1) == FALSE)
			{
				return MatchStr(pszDllName + 1, pszDllFormat);
			}
		}
		return TRUE;
	}
	return FALSE;
}

//辅助函数，将DllName和FuncName分割出来
void SplitStringForDllAndFunc(const char *pszPath, char *pszDllName, char *pszFuncName) {
	int nPathLen = strlen(pszPath);
	for (int i = 0; i < nPathLen; i++) {
		if (pszPath[i] == '.') {
			memcpy(pszDllName, pszPath, i);
			memcpy(pszFuncName, pszPath + i + 1, nPathLen - i - 1);
			break;
		}
	}
}

//判断是否时UNC路径格式
BOOL IsUNCPath(LPCSTR pszPath) {
	int nPathLen = 0;
	LPCSTR tempPath = NULL;
	if (pszPath == NULL) {
		return FALSE;
	}
	if ((nPathLen = strlen(pszPath)) < 5) {
		return FALSE;
	}
	if (pszPath[0] != '\\') {
		return FALSE;
	}
	if (pszPath[1] != '\\' && pszPath[1] != '/' && pszPath[1] != '?') {
		return FALSE;
	}
	if (pszPath[2] != '.' && pszPath[2] != '?') {
		return TRUE;
	}
	if (pszPath[strspn(pszPath, ".?/\\")] != 0) {
		tempPath = &pszPath[strspn(pszPath, ".?/\\")];
	}
	if (tempPath) {
		if (strncmp("unc", tempPath, 3) == 0) {
			wchar_t wcUncBehind = *(tempPath + 3);
			if (wcUncBehind != 0) {
				if (wcUncBehind != '.') {

				}
				else {
					wcUncBehind = *(tempPath + 3 + 1);
					if (wcUncBehind == 0) {
						return FALSE;
					}
				}

				if (wcUncBehind == '\\') {
					return TRUE;
				}
				else {
					if (wcUncBehind == '/') {
						return TRUE;
					}
				}
			}
		}
	}
	return FALSE;
}

BOOL IsExecutableAddress(LPVOID VirtualAddress)
{

	BOOL IsOk = FALSE;
	MEMORY_BASIC_INFORMATION MemoryBasicInfo = { 0 };
	VirtualQuery(VirtualAddress, &MemoryBasicInfo, sizeof(MEMORY_BASIC_INFORMATION));
	if ((MemoryBasicInfo.State == MEM_COMMIT && (MemoryBasicInfo.Protect & PAGE_EXECUTE_FLAGS)))
	{
		IsOk = TRUE;
	}
	return IsOk;
}

DWORD ErrorReport() {

	//MessageBoxA();
	TerminateProcess(GetCurrentProcess(), -1);
	return 0;
}


HMODULE proxy_GetModuleHandleEx(LPCTSTR lpModuleName) {
	HMODULE hModule = NULL;
	BOOL bRet = GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		lpModuleName,
		&hModule);

	if (bRet) {  
		return hModule;
	}

	return 0;
}
DWORD proxy_NtAllocateVirtualMemory(PVOID BaseAddr_, SIZE_T RegionSize_) {
	PVOID BaseAddr = BaseAddr_;
	SIZE_T RegionSize = RegionSize_;
	NTALLOCATEVIRTUALMEMORY pNtAllocateVirtualMemory = (NTALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtAllocateVirtualMemory");
	return pNtAllocateVirtualMemory(GetCurrentProcess(), &BaseAddr, 0, &RegionSize, MEM_RESERVE, PAGE_NOACCESS);
}




