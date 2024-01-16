#include <windows.h>
#include <stdio.h>
#include "sysc.h"
DWORD ntsize;
PVOID ntcode;
//int1 to trigger EXCEPTION_SINGLE_STEP
#define TRACE asm("INT1");
LONG WINAPI hand(EXCEPTION_POINTERS *pExceptionInfo){
    static DWORD64 rcx, rdx, r9, r8; //holds register vals
    static int exec, sysc, curri, append;
    static void* enters[10000]={0};
    static void* exits[10000]={0};
    void* rip = (void*)(pExceptionInfo->ContextRecord->Rip);
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP){
        if(!exec && (rip >= ntcode) && (rip < (ntcode+ntsize))){ //did we just enter ntdll?
            exec = 1;
            //check for syscall address in cache
            int exist = -1;
            for(int i=0;i<curri;i++){
                if(enters[i]==rip){
                    exist = i;
                    break;
                }
            }
            sysc = getsysc((unsigned long long int)rip); //find syscall number
            //store and flush registers
            rcx = pExceptionInfo->ContextRecord->Rcx;
            rdx = pExceptionInfo->ContextRecord->Rdx;
            r9 = pExceptionInfo->ContextRecord->R9;
            r8 = pExceptionInfo->ContextRecord->R8;
            pExceptionInfo->ContextRecord->Rcx = 0;
            pExceptionInfo->ContextRecord->Rdx = 0;
            pExceptionInfo->ContextRecord->R9 = 0;
            pExceptionInfo->ContextRecord->R8 = 0;
            if(exist!=-1){
                //use hwbp tracing
                printf("Tracing using HWBP...\n");
                CONTEXT ctx;
                ctx.Dr0 = (unsigned long long)exits[exist];
                ctx.Dr7 = 1 << 0 | 1 << 10;
                ctx.Dr6 = 0;
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                //we need to use SetThreadContext as debug registers are privileged
                //but since used on self, shld be fine
                SetThreadContext(GetCurrentThread(), &ctx);
                return EXCEPTION_CONTINUE_EXECUTION;
            }else{
                //single step, very slow
                printf("Cached address not found! Manually stepping, this will take a while...\n");
                enters[curri] = rip;
                append = 1;
            }
        }
        //reached syscall opcode
        if(memcmp((unsigned char*)rip, (unsigned char*)"\x0f\x05", 2)==0){
            //check if we're at right syscall
            if(sysc!=pExceptionInfo->ContextRecord->Rax){
                goto cont;
            }
            //save to cache if not done yet
            if(append){
                append = 0;
                exits[curri++] = rip;
            }
            printf("Traced!\n");
            //unset debug registers
            CONTEXT ctx;
            ctx.Dr0 = 0;
            ctx.Dr7 = 0;
            ctx.Dr6 = 0;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            SetThreadContext(GetCurrentThread(), &ctx);
            exec = 0;
            //restore registers. note we set R10 to rcx, this is because ntdll will mov r10, rcx
            //so since we alr bypass that, we do it manually
            pExceptionInfo->ContextRecord->R10 = rcx;
            pExceptionInfo->ContextRecord->Rdx = rdx;
            pExceptionInfo->ContextRecord->R9 = r9;
            pExceptionInfo->ContextRecord->R8 = r8;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    cont:
        //enable trap flag
        pExceptionInfo->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
PVOID init(){
    //syscall hunting
    hunt();
    //get size and address of ntdll .text
    PVOID imageBase = getNtdllAddr();
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS64 nth = (PIMAGE_NT_HEADERS64)(imageBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER nttext = IMAGE_FIRST_SECTION(nth);
    ntcode = imageBase + nttext->VirtualAddress;
    ntsize = nttext->SizeOfRawData;
    //register the VEH
    return AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)hand);
}
