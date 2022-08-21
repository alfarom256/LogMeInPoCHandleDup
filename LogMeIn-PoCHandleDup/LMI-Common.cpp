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

HANDLE HandleSearchThread(DWORD64 hBegin, DWORD dwAccessMask) {
	PUBLIC_OBJECT_BASIC_INFORMATION pobi = { 0 };
	HANDLE hCurrentProc = (HANDLE)-1;
	HANDLE hTargetHandle = 0;
	BOOL bRes = FALSE;
	NTSTATUS status;
	// try to search for the handle 10 times, looping over handle values from hBegin to 0x500
	for (size_t i = 0; i < 100; i++)
	{
		for (size_t j = hBegin; j < 0x500; j += 4)
		{
			ULONG ulBytesReturned = 0;
			status = NtQueryObject((HANDLE)j, (OBJECT_INFORMATION_CLASS)0, &pobi, sizeof(PUBLIC_OBJECT_BASIC_INFORMATION), &ulBytesReturned);

			if (!status) {
				printf("-");
				bRes = DuplicateHandle(g_hCurrentProc, (HANDLE)j, g_hCurrentProc, &hTargetHandle, 0, 0, DUPLICATE_SAME_ACCESS);
				if (bRes) {
					printf("Got Handle - %p - %lx - %lx\n", (HANDLE)j, pobi.Attributes, pobi.GrantedAccess);
					return hTargetHandle;
				}
			}
			else if(status != 0xC0000008){
				printf("%llx\n", status);
			}
		}
	}

	return 0;
}