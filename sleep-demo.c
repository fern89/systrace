//demo for sleep to do stack analysis, compile same way as mass-detect.c
#include <windows.h>
#include <stdio.h>
#include "unhook.h"
typedef NTSTATUS(NTAPI *d_NtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
d_NtDelayExecution NtDelayExecution;
char origbytes[12] = {0};
unsigned char newbytes[12] = "\x48\xB8\x69\x99\x67\x99\x96\x96\x06\x00\x50\xC3";
NTSTATUS hookedsleep(BOOLEAN a, PLARGE_INTEGER b){
    printf("sleep detected! pointer to sleep duration -> 0x%p\n", b);
    memcpy(NtDelayExecution, origbytes, 12);
    NTSTATUS out = NtDelayExecution(a, b);
    memcpy(NtDelayExecution, newbytes, 12);
    return out;
}
int main(){
    NtDelayExecution = (d_NtDelayExecution)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
    memcpy(origbytes, NtDelayExecution, 12);
    unsigned long long asdf = (unsigned long long)hookedsleep;
    memcpy(newbytes+2, &asdf, 8);
    DWORD old = 0;
    VirtualProtect(NtDelayExecution, 12, PAGE_EXECUTE_READWRITE, &old);
    memcpy(NtDelayExecution, newbytes, 12);
    //before unhook
    Sleep(1000);
    init();
    //after unhook, pointer should now be null
    Sleep(1000);
    return 0;
}

