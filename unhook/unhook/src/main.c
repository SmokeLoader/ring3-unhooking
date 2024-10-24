// main.c
// 2024
// Telegram: https://t.me/strikelab
// Discord: @patchguard
// Tox: 5BCB80569AC334FDA5B7806ABC05DDFE3AF8F126E08D0EA6D21DA3C13B43F164188C3EEE89E9
// unhook ring3

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include "unhook/unhook.h"

int main() {
    system("start https://t.me/strikelab");
    Sleep(1000);

    // unhook DLLs
    unhookDll(GetCurrentProcess(), L"ntdll.dll");
    unhookDll(GetCurrentProcess(), L"advapi32.dll");
    unhookDll(GetCurrentProcess(), L"sechost.dll");
    unhookDll(GetCurrentProcess(), L"pdh.dll");
    unhookDll(GetCurrentProcess(), L"amsi.dll");

    EnableDebugPrivilege();

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to create process snapshot\n");
        return 1;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        printf("[!] Failed to get first process\n");
        CloseHandle(hProcessSnap);
        return 1;
    }

    do {
        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
        if (processHandle != NULL) {

            if (wcscmp(pe32.szExeFile, L"dllhost.exe") == 0) {
                TerminateProcess(processHandle, 0);
            }

            else {
                unhookDll(processHandle, L"ntdll.dll");
                unhookDll(processHandle, L"advapi32.dll");
                unhookDll(processHandle, L"sechost.dll");
                unhookDll(processHandle, L"pdh.dll");
                unhookDll(processHandle, L"amsi.dll");
            }

            CloseHandle(processHandle);
        }
    } 
    while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    DeleteScheduledTask(L"$77svc64");
    DeleteScheduledTask(L"$77svc32");

    system("cls");
    printf("%s\n", "[*] Ring3 Rootkit Unhooked!");
    system("pause");

    return 0;
}
