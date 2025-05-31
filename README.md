# Native API Remote Process injection Trojan

Remote process injection trojan using Native Api stubs (dynamically resolved) and encrypted shellcode, undetected by Windows Defender
It uses dynamically resolved function pointers from ntdll.dll, (still invoking user-mode stubs), so it retrieves addresses of ntdll.dll functions at runtime to reduce static IAT footprint and uploads s
