#include "Process.h"


// Get PROCESSENTRY32 given it's ID:
PROCESSENTRY32 GetProcEntry(const DWORD &procID) {
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(procEntry);
    //std::cout << sizeof(procEntry) << std::endl;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(hSnapshot, &procEntry)) {
        do {
            //std::cout << procEntry.szExeFile << std::endl;
            if (procEntry.th32ProcessID == procID) {
                CloseHandle(hSnapshot);
                return procEntry;
            }
        } while (Process32Next(hSnapshot, &procEntry));

        CloseHandle(hSnapshot);
    }
    return procEntry;
}

// Get proccess ID given it's name:
DWORD GetProcID(const std::wstring procName) {
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(procEntry);
    //std::cout << sizeof(procEntry) << std::endl;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(hSnapshot, &procEntry)) {
        do {
            //std::cout << procEntry.szExeFile << std::endl;
            if (!wcscmp(procEntry.szExeFile, procName.c_str())) {
                CloseHandle(hSnapshot);
                return procEntry.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &procEntry));

        CloseHandle(hSnapshot);
    }
    return 0xFFFFFFFF;
}

// Get proccess name given it's ID:
QString GetProcName(const DWORD procID){
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(procEntry);
    //std::cout << sizeof(procEntry) << std::endl;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(hSnapshot, &procEntry)) {
        do {
            //std::cout << procEntry.szExeFile << std::endl;
            if (procEntry.th32ProcessID == procID) {
                CloseHandle(hSnapshot);
                return QString::fromWCharArray(procEntry.szExeFile);
            }
        } while (Process32Next(hSnapshot, &procEntry));

        CloseHandle(hSnapshot);
    }
    return "";
}

// Get ModuleEntry from module name, using toolhelp32snapshot:
MODULEENTRY32 GetModule(const DWORD &procID, const std::wstring modName) {
    MODULEENTRY32 modEntry = { 0 };

    // Snapshot of all modules in a process:
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procID);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 curr = { 0 };

        curr.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &curr)) {
            // Loop over all modules in proccess and check for a module name matching the modName argument:
            do {
                if (!wcscmp(curr.szModule, modName.c_str())) {
                    modEntry = curr;
                    //std::wcout << "Module Entry for \"" << modName << "\" found.\n";
                    break;
                }
            } while (Module32Next(hSnapshot, &curr));
        }
        CloseHandle(hSnapshot);
    }
    return modEntry;
}

bool ProcAndMod(PROCESSENTRY32 proc, MODULEENTRY32 mod){
    if(proc.dwSize && mod.dwSize){
        return true;
    }
    return false;
}









