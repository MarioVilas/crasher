#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

void usage();

#define CRASH_ACCESS_VIOLATION      1
#define CRASH_BREAKPOINT            2
#define CRASH_HEAP_OVERFLOW         3

void usage()
{
    printf( "Usage: crasher <crash type>\n"
            "crash types:\n"
            "1 - Access violation\n"
            "2 - Breakpoint\n"
            "3 - heap overflow\n");
}

int main(int argc, char* argv[])
{
    //printf("'%s'\n", GetCommandLine());

    if (argc == 1)
    {
        usage();
        return -1;
    }

    switch (atoi(argv[1]))
    {
        case CRASH_ACCESS_VIOLATION:
        {
            char *p = NULL;
            *p = 'a';
            break;
        }
        case CRASH_BREAKPOINT:
        {
            //__asm {int 3};
            FARPROC WINAPI fn = GetProcAddress(GetModuleHandle("ntdll.dll"), "DbgBreakPoint");
            fn();
            break;
        }
        case CRASH_HEAP_OVERFLOW:
        {
            char szConst[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            char *p1, *p2;
//            p1 = new char[10];
//            p2 = new char[10];
            p1 = (char *)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, 16);
            p2 = (char *)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, 16);
            strcpy(p1, szConst);
            HeapFree(GetProcessHeap(), 0, p2);
            HeapFree(GetProcessHeap(), 0, p1);
//            delete p2;
//            delete p1;
            break;
        }
    }

    return 0;
}
