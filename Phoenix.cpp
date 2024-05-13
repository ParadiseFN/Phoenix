#undef UNICODE
#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <psapi.h>
#include <TlHelp32.h>
#include "starfallPayload.h"
#include "nullrhiPatch.h"
#include <thread>

std::vector<std::string> split(const std::string& s, char delim) {
	std::stringstream ss(s);
	std::string item;
	std::vector<std::string> elems;
	while (std::getline(ss, item, delim)) {
		elems.push_back(std::move(item));
	}
	return elems;
}

bool Inject(HANDLE proc, std::string path) {
    auto pathStr = path.c_str();
    auto pathSize = path.size() + 1;
    std::ifstream c(path);
    if (c.fail()) return !printf("Failed to open %s!\n", pathStr);
    c.close();
    void* nameRegion = VirtualAllocEx(proc, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(proc, nameRegion, pathStr, pathSize, NULL);

    HANDLE tr = CreateRemoteThread(proc, 0, 0, (LPTHREAD_START_ROUTINE) LoadLibraryA, nameRegion, 0, 0); // this works because loadlibrarya address is the same in every binary
    WaitForSingleObject(tr, (DWORD)-1);
    CloseHandle(tr);
    VirtualFreeEx(proc, nameRegion, pathSize, MEM_RELEASE);
    return true;
}
HANDLE fnStdoutRd = NULL;
HANDLE fnStdoutWr = NULL;

void killProcessByName(const char* filename)
{
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof(pEntry);
    BOOL hRes = Process32First(hSnapShot, &pEntry);
    while (hRes)
    {
        if (strcmp(pEntry.szExeFile, filename) == 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
                (DWORD)pEntry.th32ProcessID);
            if (hProcess != NULL)
            {
                TerminateProcess(hProcess, 9);
                CloseHandle(hProcess);
            }
        }
        hRes = Process32Next(hSnapShot, &pEntry);
    }
    CloseHandle(hSnapShot);
}

std::map<std::string, std::string> config{};
TCHAR p[MAX_PATH];
bool goEnd = false;
DWORD StdoutThread(LPVOID pi) {
    PROCESS_INFORMATION processInfo = *(PROCESS_INFORMATION *) pi;
    char chBuf[4096];
    DWORD dwRead;
    bool check = true;
    while (true) {
        bool bSuccess = ReadFile(fnStdoutRd, chBuf, 4096, &dwRead, NULL);
        if (!bSuccess) break;
        if (dwRead == 0) continue;
        if (check) {
            auto s = std::string(chBuf);
            if (s.contains("CreatingParty")) { // proper !
                if (!Inject(processInfo.hProcess, config["gameserver"].find(":\\") != std::string::npos ? config["gameserver"] : std::string((char*)p) + "\\" + config["gameserver"])) {
                    TerminateProcess(processInfo.hProcess, 0);
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);
                    //goto end;
                    goEnd = true;
                }
                check = false;
            }
            else if (s.contains("[UOnlineAccountCommon::ForceLogout] ForceLogout (")) {
                auto logoutReasonStart = s.find("reason \"") + 8;
                auto logoutReasonEnd = s.substr(logoutReasonStart).find("\"");
                printf("Failed to login: %s\n", s.substr(logoutReasonStart, logoutReasonEnd).c_str());
                TerminateProcess(processInfo.hProcess, 0);

                check = false;
            }
        }
    }
    return 0;   
}

int main()
{
	std::ifstream c("config.txt");
    if (c.fail()) {
        std::ofstream cn("config.txt");
        cn << 
            "# Game path\n"
            "path=\n"
            "# Backend IP in format http(s)://ip:port\n"
            "backend=\n"
            "# Gameserver path\n"
            "gameserver=\n"
            "# Gameserver account email\n"
            "email=\n"
            "# Gameserver account password\n"
            "password=\n";
        cn.close();
        printf("Failed to find config.txt! A blank one for you to configure has been created.\n");
        while (true) {}
    }
	std::string line;
	while (std::getline(c, line)) {
        if (line.starts_with('#')) continue;
        auto s = split(line, '=');
		if (s.size() > 1) config[s[0]] = s[1];
	}
    c.close();
    if (!config.contains("path") || !config.contains("backend") || !config.contains("gameserver") || !config.contains("email") || !config.contains("password")) {
        printf("Config does not have all required values!\n");
        while (true) {}
    }
    auto fn = config["path"];
    std::ifstream f(fn + "\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe");
    if (!f.is_open()) {
        printf("Path is not a valid Fortnite install!\n");
        while (true) {}
    }
    f.close();
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&fnStdoutRd, &fnStdoutWr, &saAttr, 0)) {
        printf("Failed to open stdout pipe!\n");
        while (true) {}
    }
    if (!SetHandleInformation(fnStdoutRd, HANDLE_FLAG_INHERIT, 0)) {
        printf("Failed to open disable inherit on stdout pipe!\n");
        while (true) {}
    }

    TCHAR lpTempPathBuffer[MAX_PATH];

    auto dwRetVal = GetTempPathA(MAX_PATH, lpTempPathBuffer);
    if (dwRetVal > MAX_PATH || (dwRetVal == 0))
    {
        printf("Failed to get temp path!\n");
        while (true) {}
    }

    std::string goofy = std::string(lpTempPathBuffer) + "\\Starfall.dll";
    std::ofstream file(goofy.c_str(), std::ios::binary);
    file.write((const char *) Starfall, sizeof(Starfall));
    file.close();

    std::string nullrhi = std::string(lpTempPathBuffer) + "\\NullrhiPatch.dll";
    std::ofstream nullrhiF(nullrhi.c_str(), std::ios::binary);
    nullrhiF.write((const char*)NullrhiPatch, sizeof(NullrhiPatch));
    nullrhiF.close();

    killProcessByName("FortniteClient-Win64-Shipping.exe");
    killProcessByName("FortniteClient-Win64-Shipping_EAC.exe");
    killProcessByName("FortniteLauncher.exe");

    STARTUPINFOA info = { sizeof(info) };
    ZeroMemory(&info, sizeof(STARTUPINFOA));
    info.cb = sizeof(STARTUPINFOA);
    info.hStdOutput = fnStdoutWr;
    info.dwFlags |= STARTF_USESTDHANDLES;
    STARTUPINFOA Nuh = { sizeof(info) };
    PROCESS_INFORMATION Uh;
    CreateProcessA((fn + "\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping_EAC.exe").c_str(), (char*)"", NULL, NULL, true, CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, fn.c_str(), &Nuh, &Uh);
    STARTUPINFOA Plo = { sizeof(info) };
    PROCESS_INFORMATION Osh;
    CreateProcessA((fn + "\\FortniteGame\\Binaries\\Win64\\FortniteLauncher.exe").c_str(), (char*)"", NULL, NULL, true, CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, fn.c_str(), &Plo, &Osh);
    GetCurrentDirectoryA(MAX_PATH, (LPSTR)p);
    bool firstStart = true;
    while (true) {
        if (firstStart) {
            printf("Starting server...\n");
            firstStart = false;
        }
        else {
            printf("Restarting server...\n");
        }
        std::string params = fn + "\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe -epicapp=Fortnite -epicenv=Prod -epicportal -skippatchcheck -nobe -fromfl=eac -fltoken=3db3ba5dcbd2e16703f3978d -caldera=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50X2lkIjoiYmU5ZGE1YzJmYmVhNDQwN2IyZjQwZWJhYWQ4NTlhZDQiLCJnZW5lcmF0ZWQiOjE2Mzg3MTcyNzgsImNhbGRlcmFHdWlkIjoiMzgxMGI4NjMtMmE2NS00NDU3LTliNTgtNGRhYjNiNDgyYTg2IiwiYWNQcm92aWRlciI6IkVhc3lBbnRpQ2hlYXQiLCJub3RlcyI6IiIsImZhbGxiYWNrIjpmYWxzZX0.VAWQB67RTxhiWOxx7DBjnzDnXyyEnX7OljJm-j2d88G_WgwQ9wrE6lwMEHZHjBd1ISJdUO1UVUqkfLdU5nofBQ -nullrhi -nosound -nosplash";
        PROCESS_INFORMATION processInfo;
        CreateProcessA((fn + "\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe").c_str(), (char*)(params + " -AUTH_LOGIN=" + config["email"] + " -AUTH_PASSWORD=" + config["password"] + " -AUTH_TYPE=epic -backend=" + config["backend"]).c_str(), NULL, NULL, true, CREATE_SUSPENDED, nullptr, fn.c_str(), &info, &processInfo);
        if (!Inject(processInfo.hProcess, nullrhi)) {
            TerminateProcess(processInfo.hProcess, 0);
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
            goto end;
        }

        HANDLE tsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        THREADENTRY32 ent;
        ent.dwSize = sizeof(THREADENTRY32);
        Thread32First(tsnap, &ent);

        while (Thread32Next(tsnap, &ent)) {
            if (ent.th32OwnerProcessID == processInfo.dwProcessId) {
                HANDLE thr = OpenThread(THREAD_ALL_ACCESS, FALSE, ent.th32ThreadID);

                ResumeThread(thr);
                CloseHandle(thr);
            }
        }
        CloseHandle(tsnap);

        if (!Inject(processInfo.hProcess, goofy)) {
            TerminateProcess(processInfo.hProcess, 0);
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
            goto end;
        }
        auto t = CreateThread(0, 0, StdoutThread, &processInfo, 0, 0);
        WaitForSingleObject(processInfo.hProcess, (DWORD)-1);
        TerminateThread(t, 0);
        if (goEnd) goto end;

        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }

end:
    TerminateProcess(Uh.hProcess, 0);
    CloseHandle(Uh.hProcess);
    CloseHandle(Uh.hThread);
    TerminateProcess(Osh.hProcess, 0);
    CloseHandle(Osh.hProcess);
    CloseHandle(Osh.hThread);
}