# systrace
Bypass usermode hooking, while preserving full stack frame. Built for x64.

## Technique
We register a VEH handler, then call INT1 to trigger it. We flush registers rcx, rdx, r8, and r9, saving them elsewhere, and continue execution. For first execution, we single-step till we reach a syscall (which will take a while), for subsequent executions, we set a hardware breakpoint on the address of the syscall instruction (much faster). Once we reach syscall, we restore all registers. This means any usermode EDR hooks will see the registers as if they were all NULL, making it impossible to detect what arguments the winapi is using, hence easily bypassing usermode EDR hooks. Unlike manual syscalling, this method falls through whatever hooks the EDR has in place, making it impossible to distinguish from genuine calls via thread stack inspection from InstrumentationCallbacks.

## Demonstration
![image](https://github.com/fern89/systrace/assets/139056562/8f41a2bc-0f90-4b74-9779-9effad43f391)

As can be seen in stack item 6, we can observe that the hook is called, indicating that stack analysis will not trigger any alerts.

## Compilation
Compiled with mingw gcc using `x86_64-w64-mingw32-gcc systrace.c`, and `x86_64-w64-mingw32-gcc mass-unhook.c rop.S -masm=intel`

## Tooling integration
Include the `trace.h` header, call `init()`, then add the `TRACE` macro in front of any ntdll call you would like to unhook. Or, you can also include the `unhook.h` header, call `init()`, and all ntdlls that kernel32 functions call down to, will be automatically unhooked for you.

## Possible improvements
Currently, the single-step execution is EXTREMELY slow. It may be possible to use the Page Guard hooking method so that the program can run win32 APIs uninterrupted, only resuming single-stepping once exiting the function.
