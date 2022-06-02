#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

#define processName "target.exe"
#define dllName "lib.dll"
#define RenameInj true

std::string GetExeDirectory()
{
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return std::string(buffer);
}

void InjRename()
{
    std::string path = GetExeDirectory();
    std::string exe = path.substr(path.find_last_of("\\") + 1, path.size());

    srand(time(0));
    char characters[] = "qwertyuiopasdfghjklzxcvbnm";
    char newname[16];

    int z = rand() % 4 + 10;
    for (int i = 0; i < z; i++)
    {
        char x = characters[rand() % 26];
        newname[i] = x;
    }

    strcat_s(newname, ".exe\0");
    rename(exe.c_str(), newname);
}

DWORD GetProcIDByName(const char* procName) {
    HANDLE hSnap;
    BOOL done;
    PROCESSENTRY32 procEntry;

    ZeroMemory(&procEntry, sizeof(PROCESSENTRY32));
    procEntry.dwSize = sizeof(PROCESSENTRY32);

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    done = Process32First(hSnap, &procEntry);
    do {
        if (_strnicmp(procEntry.szExeFile, procName, sizeof(procEntry.szExeFile)) == 0) {
            return procEntry.th32ProcessID;
        }
    } while (Process32Next(hSnap, &procEntry));

    return 0;
}

BOOL InjectDll()
{
    std::cout << "[+] waiting for " << processName << std::endl;
    DWORD procID = GetProcIDByName(processName);
    while (procID == 0)
    {
        Sleep(5000);
        procID = GetProcIDByName(processName);
    }
    std::cout << "[+] pid: " << procID << std::endl;

    std::string::size_type pos = std::string(GetExeDirectory()).find_last_of("\\/");
    std::string fullDllName = GetExeDirectory().substr(0, pos) + "\\" + dllName;
    auto fDN = fullDllName.c_str();

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if (hProc == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    LPVOID loadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    LPVOID remoteString = VirtualAllocEx(hProc, NULL, strlen(fDN), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(hProc, remoteString, fDN, strlen(fDN), NULL);
    CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibrary, (LPVOID)remoteString, NULL, NULL);
    return TRUE;
}

int main()
{
    if (RenameInj)
        InjRename();
    if (InjectDll())
    {
        std::cout << "[+] success" << std::endl;
    }
    else
    {
        std::cout << "[+] failed to inject" << std::endl;
    }
    Sleep(5000);
    return 0;
}