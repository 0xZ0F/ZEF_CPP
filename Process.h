#ifndef PROCESS_H
#define PROCESS_H
#include <Windows.h>
#include <TlHelp32.h>
#include <QString>
PROCESSENTRY32 GetProcEntry(const DWORD &procID);
DWORD GetProcID(const std::wstring procName);
QString GetProcName(const DWORD procID);
MODULEENTRY32 GetModule(const DWORD &procID, const std::wstring modName);
bool ProcAndMod(PROCESSENTRY32 proc, MODULEENTRY32 mod);
#endif // PROCESS_H
