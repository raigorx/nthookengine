// NtHookEngine_Test.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "NtHookEngine_Test.h"

BOOL (__cdecl *HookFunction)(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction);
VOID (__cdecl *UnhookFunction)(ULONG_PTR Function);
ULONG_PTR (__cdecl *GetOriginalFunction)(ULONG_PTR Hook);

int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption,
						 UINT uType, WORD wLanguageId, DWORD dwMilliseconds);

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
					   LPTSTR lpCmdLine, int nCmdShow)
{
	//
	// Retrive hook functions
	// 

	HMODULE hHookEngineDll = LoadLibrary(_T("NtHookEngine.dll"));

	HookFunction = (BOOL (__cdecl *)(ULONG_PTR, ULONG_PTR))
		GetProcAddress(hHookEngineDll, "HookFunction");

	UnhookFunction = (VOID (__cdecl *)(ULONG_PTR))
		GetProcAddress(hHookEngineDll, "UnhookFunction");

	GetOriginalFunction = (ULONG_PTR (__cdecl *)(ULONG_PTR))
		GetProcAddress(hHookEngineDll, "GetOriginalFunction");

	if (HookFunction == NULL || UnhookFunction == NULL || 
		GetOriginalFunction == NULL)
		return 0;

	//
	// Hook MessageBoxTimeoutW
	//

	HookFunction((ULONG_PTR) GetProcAddress(LoadLibrary(_T("User32.dll")),
		"MessageBoxTimeoutW"), 
		(ULONG_PTR) &MyMessageBoxW);

	MessageBox(0, _T("Hi, this is a message box!"), _T("This is the title."), 
		MB_ICONINFORMATION);

	//
	// Unhook MessageBoxTimeoutW
	//

	UnhookFunction((ULONG_PTR) GetProcAddress(LoadLibrary(_T("User32.dll")), 
		"MessageBoxTimeoutW"));

	MessageBox(0, _T("Hi, this is a message box!"), _T("This is the title."), 
		MB_ICONINFORMATION);

	return 0;
}

int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType,
						 WORD wLanguageId, DWORD dwMilliseconds)
{
	int (WINAPI *pMessageBoxW)(HWND hWnd, LPCWSTR lpText, 
		LPCWSTR lpCaption, UINT uType, WORD wLanguageId, 
		DWORD dwMilliseconds);

	pMessageBoxW = (int (WINAPI *)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD))
		GetOriginalFunction((ULONG_PTR) MyMessageBoxW);

	return pMessageBoxW(hWnd, lpText, L"Hooked MessageBox",
		uType, wLanguageId, dwMilliseconds);
}

