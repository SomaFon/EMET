#include"ASR.h"
#include <atlbase.h>
#include <oleacc.h>
#include <mshtml.h>

BOOL CALLBACK EnumSubWndFunc(HWND hWnd, LPARAM lParam)
{
	TCHAR szClassName[26] = { 0 };

	if (GetClassName(hWnd, szClassName, 26) == 24) {
		if (_tcscmp(szClassName, _T("Internet Explorer_Server")) == 0) {
			if (GetWindowThreadProcessId(hWnd, 0) == GetCurrentThreadId()) {
				*(DWORD*)lParam = (LPARAM)hWnd;
				return FALSE;
			}
		}
	}

	return TRUE;
}
BOOL CALLBACK EnumWndFunc(HWND hWndParent, LPARAM lParam)
{
	*(DWORD*)lParam = 0;
	if (MatchClassName(hWndParent)) {
		EnumChildWindows(hWndParent, EnumSubWndFunc, lParam);
	}

	return *(DWORD*)lParam == 0;
}
HRESULT GetIHtmlDoc(HWND hWnd, IHTMLDocument2 **ppDoc)
{
	DWORD dwResult = 0;
	UINT MsgID = RegisterWindowMessage(_T("WM_HTML_GETOBJECT"));
	if (MsgID == 0) {
		return NULL;
	}

	HMODULE hMod = LoadLibrary(_T("oleacc.dll"));
	if (hMod == 0) {
		return NULL;
	}

	PVOID pObjectFromLresult = GetProcAddress(hMod, "ObjectFromLresult");
	if (pObjectFromLresult == NULL) {
		return NULL;
	}

	SendMessageTimeoutW(hWnd, MsgID, 0, 0, 2u, 1000u, &dwResult);

	return ((OBJECTFROMLRESULT)pObjectFromLresult)(dwResult, IID_IHTMLDocument2, 0, (void**)ppDoc);
}


IInternetSecurityManager* GetIInternetSecurityManager() {
	IInternetSecurityManager *pSecurityManager = NULL;
	HRESULT hResult = CoCreateInstance(CLSID_InternetSecurityManager, 0,
		CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER,
		IID_IInternetSecurityManager, (LPVOID*)&pSecurityManager);

	if (hResult == S_OK) {
		return pSecurityManager;
	}

	return NULL;
}

DWORD CheckURLZone() {
	HWND hWnd = 0;
	EnumWindows(EnumWndFunc, (LPARAM)&hWnd);

	if (hWnd != 0) {
		IHTMLDocument2 *pDoc = NULL;
		HRESULT hResult = GetIHtmlDoc(hWnd, &pDoc);
		BSTR bstrURL;
		if (hResult != S_OK) {
			return 0;
		}

		IInternetSecurityManager *pSecurityManager = GetIInternetSecurityManager();
		hResult = pDoc->get_URL(&bstrURL);
		if (hResult != S_OK) {
			return 0;
		}

		DWORD dwZone = 0;
		pSecurityManager->MapUrlToZone(bstrURL, &dwZone, 0);
		if (hResult != S_OK) {
			return 0;
		}

		return dwZone;
	}
	return 0;
}

int MatchClassName(HWND hWnd)
{
	int nLen = 0;
	int nCmpResult = 0;
	TCHAR szwClassName[20] = { 0 };

	nLen = GetClassName(hWnd, szwClassName, 0xB);
	if (nLen == 9)
	{
		nCmpResult = _tcscmp(szwClassName, _T("Frame Tab"));
	}
	else
	{
		if (nLen != 7)
			return 0;
		nCmpResult = _tcscmp(szwClassName, _T("IEFrame"));
	}

	if (!nCmpResult) {
		return 1;
	}
	return 0;
}

