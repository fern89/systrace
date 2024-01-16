#include <windows.h>
#include <stdio.h>
#include "trace.h"
typedef NTSTATUS(NTAPI *d_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
d_NtWriteVirtualMemory NtWriteVirtualMemory;
char origbytes[12] = {0};
unsigned char newbytes[12] = "\x48\xB8\x69\x99\x67\x99\x96\x96\x06\x00\x50\xC3";
//sample hook to demo NtWriteVirtualMemory
NTSTATUS NTAPI hookedwvm(HANDLE a, PVOID b, PVOID c, ULONG d, PULONG e){
    MessageBoxA(NULL, c, "NtWriteVirtualMemory detected!!!", MB_OK);
    memcpy(NtWriteVirtualMemory, origbytes, 12);
    NTSTATUS out = NtWriteVirtualMemory(a, b, c, d, e);
    memcpy(NtWriteVirtualMemory, newbytes, 12);
    return out;
}
int main(){
    init();
    //apply hook
    NtWriteVirtualMemory = (d_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    memcpy(origbytes, NtWriteVirtualMemory, 12);
    unsigned long long asdf = (unsigned long long)hookedwvm;
    memcpy(newbytes+2, &asdf, 8);
    DWORD old = 0;
    VirtualProtect(NtWriteVirtualMemory, 12, PAGE_EXECUTE_READWRITE, &old);
    memcpy(NtWriteVirtualMemory, newbytes, 12);

    //demo
    char demo[] = "lorem";
    char tochange[] = "ipsum";
    printf("%s\n", demo);
    NtWriteVirtualMemory(GetCurrentProcess(), demo, tochange, 5, NULL); //observe the MessageBox shows the tochange text
    TRACE NtWriteVirtualMemory(GetCurrentProcess(), demo, tochange, 5, NULL); //observe the MessageBox is blank
    TRACE NtWriteVirtualMemory(GetCurrentProcess(), demo, tochange, 5, NULL); //demo for HWBP, will run much faster this time
    printf("%s\n", demo);
    return 0;
}
