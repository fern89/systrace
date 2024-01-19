#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "sysc.h"
extern void* sysc();
DWORD ntsize;
PVOID ntcode;
typedef NTSTATUS(NTAPI *d_NtSetContextThread)(HANDLE, PCONTEXT);
d_NtSetContextThread NtSetContextThread;
static void* getDllAddr(const wchar_t * DllNameToSearch){
    PLDR_DATA_TABLE_ENTRY pDataTableEntry = 0;
    PVOID DLLAddress = 0;
    PPEB pPEB = (PPEB) __readgsqword(0x60);
    PPEB_LDR_DATA pLdr = pPEB->Ldr;
    PLIST_ENTRY AddressFirstPLIST = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY AddressFirstNode = AddressFirstPLIST->Flink;
    for (PLIST_ENTRY Node = AddressFirstNode; Node != AddressFirstPLIST ;Node = Node->Flink){
        Node = Node - 1;
        pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)Node;
        wchar_t * FullDLLName = (wchar_t *)pDataTableEntry->FullDllName.Buffer;
        for(int size = wcslen(FullDLLName), cpt = 0; cpt < size ; cpt++){
    		FullDLLName[cpt] = tolower(FullDLLName[cpt]);
    	}
        if(wcsstr(FullDLLName, DllNameToSearch) != NULL){
            DLLAddress = (PVOID)pDataTableEntry->DllBase;
            return DLLAddress;
        }
        Node = Node + 1;
    }

    return DLLAddress;
}
static int unhook(){
    //kernel32.dll actually calls down to kernelbase.dll. unhooking kernel32.dll's IAT is fully ineffective.
    LPVOID imageBase = getDllAddr(L"kernelbase.dll");
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
    LPCSTR libraryName = NULL;
    PIMAGE_IMPORT_BY_NAME functionName = NULL; 
    while (importDescriptor->Name){
        libraryName = (LPCSTR)(importDescriptor->Name + imageBase);
        if(strcmp(libraryName, "ntdll.dll")==0){
            break;
        }
        importDescriptor++;
    }
    PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
    originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
    firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);
    PIMAGE_THUNK_DATA bft = originalFirstThunk;
    while (bft->u1.AddressOfData) bft++;
    DWORD oldProtect = 0;
    LPVOID ft = (LPVOID)(&firstThunk->u1.Function);
    size_t sz = sizeof(void*) * (unsigned long long)(bft-originalFirstThunk);
    VirtualProtect(ft, sz, PAGE_READWRITE, &oldProtect);
    while (originalFirstThunk->u1.AddressOfData){
        functionName = (PIMAGE_IMPORT_BY_NAME)(imageBase + (unsigned int)originalFirstThunk->u1.AddressOfData);
        char* name = functionName->Name;
        if (memcmp(name, "Nt", 2)==0 && memcmp(name, "Ntdll", 5)!=0){
            int syscall = getsysc(firstThunk->u1.Function);
            if(syscall!=-1){
                firstThunk->u1.Function = (DWORD_PTR)((unsigned char*)sysc+(syscall*10));
            }
        }
        ++originalFirstThunk;
        ++firstThunk;
    }
    VirtualProtect(ft, sz, oldProtect, &oldProtect);
    return 0;
}
static LONG WINAPI hand(EXCEPTION_POINTERS *pExceptionInfo){
    static DWORD64 rcx, rdx, r9, r8;
    static int exec, sysc, curri, append;
    static void* enters[10000]={0};
    static void* exits[10000]={0};
    void* rip = (void*)(pExceptionInfo->ContextRecord->Rip);
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP){
        if(!exec && (rip >= ntcode) && (rip < (ntcode+ntsize))){
            exec = 1;
            int exist = -1;
            for(int i=0;i<curri;i++){
                if(enters[i]==rip){
                    exist = i;
                    break;
                }
            }
            sysc = getsysc((unsigned long long int)rip);
            rcx = pExceptionInfo->ContextRecord->Rcx;
            rdx = pExceptionInfo->ContextRecord->Rdx;
            r9 = pExceptionInfo->ContextRecord->R9;
            r8 = pExceptionInfo->ContextRecord->R8;
            pExceptionInfo->ContextRecord->Rcx = 0;
            pExceptionInfo->ContextRecord->Rdx = 0;
            pExceptionInfo->ContextRecord->R9 = 0;
            pExceptionInfo->ContextRecord->R8 = 0;
            if(exist!=-1){
                printf("Tracing using HWBP...\n");
                CONTEXT ctx;
                ctx.Dr0 = (unsigned long long)exits[exist];
                ctx.Dr7 = 1 << 0 | 1 << 10;
                ctx.Dr6 = 0;
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                NtSetContextThread((HANDLE)-2, &ctx);
                return EXCEPTION_CONTINUE_EXECUTION;
            }else{
                printf("Cached address not found! Manually stepping, this will take a while...\n");
                enters[curri] = rip;
                append = 1;
            }
        }
        if(memcmp((unsigned char*)rip, (unsigned char*)"\x0f\x05", 2)==0){
            if(sysc!=pExceptionInfo->ContextRecord->Rax){
                goto cont;
            }
            if(append){
                append = 0;
                exits[curri++] = rip;
            }
            printf("Traced!\n");
            CONTEXT ctx;
            ctx.Dr0 = 0;
            ctx.Dr7 = 0;
            ctx.Dr6 = 0;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            NtSetContextThread((HANDLE)-2, &ctx);
            exec = 0;
            pExceptionInfo->ContextRecord->R10 = rcx;
            pExceptionInfo->ContextRecord->Rdx = rdx;
            pExceptionInfo->ContextRecord->R9 = r9;
            pExceptionInfo->ContextRecord->R8 = r8;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    cont:
        pExceptionInfo->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
PVOID init(){
    NtSetContextThread = (d_NtSetContextThread)GetProcAddress(getNtdllAddr(), "NtSetContextThread");
    hunt();
    PVOID imageBase = getNtdllAddr();
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS64 nth = (PIMAGE_NT_HEADERS64)(imageBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER nttext = IMAGE_FIRST_SECTION(nth);
    ntcode = imageBase + nttext->VirtualAddress;
    ntsize = nttext->SizeOfRawData;
    PVOID veh = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)hand);
    unhook();
    return veh;
}
