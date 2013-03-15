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

#ifndef _M_AMD64
const BYTE RedirectBytes[6] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0xC3 }; // JMP 00000000; RET;
#else
const BYTE RedirectBytes[13] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0, 0xC3 }; // MOV RAX, 0000000000000000; JMP RAX; RET;
#endif

const wchar_t* k_lpAttachNotification = L"RELOCALE_ATTACH_NOTIFICATION";

BOOL redirectFunction(LPCWSTR lpszModule, LPCSTR lpszFunction, LPVOID lpCustomFunction) {
	HMODULE hLib = GetModuleHandle(lpszModule);
	if (hLib == 0) {
		return FALSE;
	}
	BYTE* lpFunction = (BYTE*) GetProcAddress(hLib, lpszFunction);
	if (lpFunction == 0) {
		return FALSE;
	}

	DWORD oldProtect = 0;
	if (!VirtualProtect(lpFunction, sizeof(RedirectBytes), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		return FALSE;
	}
	memcpy(lpFunction, RedirectBytes, sizeof(RedirectBytes));
#ifndef _M_AMD64
	uintptr_t relative = ((uintptr_t) lpCustomFunction - (uintptr_t) lpFunction - sizeof(uintptr_t) - 1);
	memcpy(lpFunction + 1, &relative, sizeof(uintptr_t));
#else
	uintptr_t address = (uintptr_t) lpCustomFunction;
	memcpy(lpFunction + 2, &address, sizeof(uintptr_t));
#endif
	DWORD temp = 0;
	VirtualProtect(lpFunction, sizeof(RedirectBytes), oldProtect, &temp);
	return TRUE;
}

int WINAPI Custom_GetUserDefaultLCID() {
	SetThreadLocale(1031);
	return 1031;
}

BOOL attachHook() {
	return redirectFunction(L"kernel32.dll", "GetUserDefaultLCID", Custom_GetUserDefaultLCID);
}

BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD reason, LPVOID lpReserved) {
	switch(reason) {
		case DLL_PROCESS_ATTACH:
			if (attachHook()) {
				wchar_t buffer[10];
				GetEnvironmentVariable(k_lpAttachNotification, buffer, 10);
				if (!wcscmp(buffer, L"1")) {
					MessageBox(0, L"Target application was successfully hooked.", L"ReLocale notification", MB_OK);
				}
				char szLibName[MAX_PATH];
				GetModuleFileNameA(hInstance, szLibName, MAX_PATH);
				LoadLibraryA(szLibName);
			}
			break;
	}
}