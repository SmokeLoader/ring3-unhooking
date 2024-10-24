// unhook.h
// 2024
// Telegram: https://t.me/strikelab
// Discord: @patchguard
// Tox: 5BCB80569AC334FDA5B7806ABC05DDFE3AF8F126E08D0EA6D21DA3C13B43F164188C3EEE89E9
// unhook ring3

#ifndef UNHOOK_H
#define UNHOOK_H

#include <windows.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <taskschd.h>
#include <stdio.h>

// Macro
// -----------------------------------------------------------
// Determine the bitness of the operating system (32-bit or 64-bit)
#define BITNESS(bits) (sizeof(LPVOID) * 8 == (bits))

// Function Declarations
// -----------------------------------------------------------

/**
 * @brief Checks if the current operating system is 64-bit.
 *
 * @return TRUE if the OS is 64-bit, FALSE if it is 32-bit.
 */
BOOL Is64BitOperatingSystem();

/**
 * @brief Unhooks a specified DLL from the given remote process.
 *
 * @param hProcess Handle to the process from which the DLL will be unhooked.
 * @param name Name of the DLL to unhook.
 */
VOID unhookDll(HANDLE hProcess, LPCWSTR name);

/**
 * @brief Enables debug privilege for the current process.
 *
 * @return TRUE if the privilege was successfully enabled, FALSE otherwise.
 */
BOOL EnableDebugPrivilege();

/**
 * @brief Deletes a scheduled task by its name.
 *
 * @param name Name of the scheduled task to delete.
 * @return TRUE if the task was successfully deleted, FALSE otherwise.
 */
BOOL DeleteScheduledTask(LPCWSTR name);

#endif // UNHOOK_H
