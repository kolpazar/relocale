/*
    ReLocale
    Copyright (C) 2013 kolpazar
    
    ReLocale is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ReLocale is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ReLocale.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Windows.h>
#include <stdio.h>
#include <fcntl.h>
#include <io.h>

const wchar_t* k_lpAttachNotification = L"RELOCALE_ATTACH_NOTIFICATION";

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	int nArgs;
	LPWSTR* lpszArgs = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	int showHelp = (nArgs < 2);
	int showAttachNotification = 0;
	LPWSTR lpszTargetCmd = NULL;

	int posArg = 0;
	while (++posArg < nArgs) {
		if (!wcscmp(lpszArgs[posArg], L"/?")) {
			showHelp = 1;
			break;
		} else if (!wcscmp(lpszArgs[posArg], L"/M")) {
			showAttachNotification = 1;
		} else {
			size_t cbTargetArgs = strlen(lpCmdLine) * sizeof(wchar_t);
			lpszTargetCmd = (wchar_t*) malloc(cbTargetArgs);
			memset(lpszTargetCmd, 0, cbTargetArgs);
			wchar_t* lpszTargetTemp = lpszTargetCmd;
			size_t nArgLength = 0;
			for (int i = posArg; i < nArgs; i++) {
				nArgLength = wcslen(lpszArgs[i]);
				wcscpy(lpszTargetTemp, lpszArgs[i]);
				if (posArg < nArgs-1) {
					lpszTargetTemp += wcslen(lpszArgs[i]);
					wcscpy(lpszTargetTemp, L" ");
					lpszTargetTemp++;
				}
			}
			break;
		}
	}
	if (showHelp) {
		MessageBox(0, L"ReLocale by kolpazar\n\nUsage: ReLocale [opts] exe [args]\n\nOpts:\n/M Display a message after hooking\n/? Display this window", L"ReLocale", MB_OK);
		return 0;
	}
	if (showAttachNotification) {
		SetEnvironmentVariable(k_lpAttachNotification, L"1");
	}
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	CreateProcess(NULL, lpszTargetCmd, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, FALSE, NULL, &si, &pi);
	
	char szHookLibrary[MAX_PATH];
#ifndef _M_AMD64
	strcpy((char*) &szHookLibrary, "ReLocaleHook.dll");
#else
	strcpy((char*) &szHookLibrary, "ReLocaleHook64.dll");
#endif
	LPVOID lpProcessMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(szHookLibrary), MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(pi.hProcess, lpProcessMem, &szHookLibrary, sizeof(szHookLibrary), NULL);

	HANDLE hDllThread = CreateRemoteThread(pi.hProcess, NULL, 0, 
		(LPTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"), lpProcessMem, 0, NULL);
	WaitForSingleObject(hDllThread, INFINITE);
	ResumeThread(pi.hThread);
	return 0;
}