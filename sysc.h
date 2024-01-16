//enumerate syscalls via FreshyCalls technique
#include <windows.h>
#include <winternl.h>
int totalFns=0;
long long int ps[10000]={0};
void bubbleSort(long long int arr[], int n){
    for (int i = 0; i < n - 1; i++){
        for (int j = 0; j < n - i - 1; j++){
            if (arr[j] > arr[j + 1]){
                long long int tmp = arr[j];
                arr[j] = arr[j+1];
                arr[j+1] = tmp;
            }
        }
    }
}
void* getNtdllAddr(){
    PPEB ProcessInformation = (PPEB)(__readgsqword(0x60));
    void* ntdll = (ProcessInformation->Ldr->InMemoryOrderModuleList.Flink->Flink);
    ntdll+=0x20;
    unsigned long long int base = 0;
    memcpy(&base, ntdll, 8);
    return (void*) base;
}
int getsysc(long long int addr){
    for(int i=0;i<totalFns;i++){
        if(ps[i] == addr) return i;
    }
    return -1;
}
int hunt(){
    HMODULE peBase = getNtdllAddr();
    PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)peBase;
    PIMAGE_NT_HEADERS imageNtHeaders = (PIMAGE_NT_HEADERS)((unsigned char*)imageDosHeader + imageDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER imageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&imageNtHeaders->OptionalHeader;
    PIMAGE_DATA_DIRECTORY imageExportDataDirectory = &(imageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)peBase + imageExportDataDirectory->VirtualAddress);
    DWORD numberOfNames = imageExportDirectory->NumberOfNames;
    PDWORD exportAddressTable = (PDWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfFunctions);
    PWORD nameOrdinalsPointer = (PWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfNameOrdinals);
    PDWORD exportNamePointerTable = (PDWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfNames);
    int c=0;
    int nameIndex = 0;
    for (nameIndex = 0; nameIndex < numberOfNames; nameIndex++){
        char* name = (char*)((unsigned char*)peBase + exportNamePointerTable[nameIndex]);
        if(memcmp(name, "Nt", 2)==0 && memcmp(name, "Ntdll", 5)!=0 && strcmp(name, "NtGetTickCount")!=0){
            WORD ordinal = nameOrdinalsPointer[nameIndex];
            unsigned char* targetFunctionAddress = ((unsigned char*)peBase + exportAddressTable[ordinal]);
            ps[c] = (long long int)targetFunctionAddress;
            c++;
        }
    }
    bubbleSort(ps, c);
    totalFns=c;
    return 0;
}
