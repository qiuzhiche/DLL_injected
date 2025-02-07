#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <shlwapi.h>  // ���� PathAppend
#pragma comment(lib, "shlwapi.lib")  // ���� shlwapi.lib
void PrintError(const std::string& msg) {
    DWORD errCode = GetLastError();
    std::cerr << msg << " Error Code: " << errCode << " (" << errCode << ")" << std::endl;
}
// ע�� DLL
bool InjectDLL(DWORD processID, const char* dllPath) {
    // ��Ŀ�����
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        PrintError("Failed to open target process");
        return false;
    }
    // ��Ŀ������з����ڴ�
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteMemory == NULL) {
        PrintError("Failed to allocate memory in target process");
        CloseHandle(hProcess);
        return false;
    }
    // �� DLL ·��д��Ŀ������ڴ�
    if (!WriteProcessMemory(hProcess, pRemoteMemory, (LPVOID)dllPath, strlen(dllPath) + 1, NULL)) {
        PrintError("Failed to write to target process memory");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    // ��ȡ LoadLibraryA ������ַ
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        PrintError("Failed to get address of LoadLibraryA");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    // ����Զ���̣߳�ִ�� LoadLibraryA
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMemory, 0, NULL);
    if (hRemoteThread == NULL) {
        PrintError("Failed to create remote thread");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    // �ȴ��߳�ִ�����
    WaitForSingleObject(hRemoteThread, INFINITE);
    // ������Դ
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);
    return true;
}
// ��ȡ��ǰ��������Ŀ¼
std::string GetCurrentDir() {
    char buffer[MAX_PATH];
    if (GetModuleFileNameA(NULL, buffer, MAX_PATH)) {
        PathRemoveFileSpecA(buffer);  // ȥ���ļ�����ֻ����Ŀ¼
        return std::string(buffer);
    }
    return "";
}
// ��ȡ���� ID
DWORD GetProcessID(const std::string& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        PrintError("Failed to create process snapshot");
        return 0;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            // ʹ�� wcscmp ���п��ַ��Ƚ�
            if (wcscmp(pe.szExeFile, std::wstring(processName.begin(), processName.end()).c_str()) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}
// ���� DLL �ļ�
std::string FindDLLInCurrentDir(const std::string& dllName) {
    std::string currentDir = GetCurrentDir();
    if (currentDir.empty()) {
        std::cerr << "Failed to get current directory." << std::endl;
        return "";
    }
    std::string dllPath = currentDir + "\\" + dllName;
    DWORD dwAttrib = GetFileAttributesA(dllPath.c_str());
    if (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
        return dllPath;
    }
    return "";  // ���ؿ��ַ�����ʾδ�ҵ� DLL �ļ�
}
// ��ȡ�����в�������֤����
bool GetUserInput(std::string& processName, std::string& dllName) {
    std::cout << "Enter target process name (e.g., MiniGameApp.exe): ";
    std::getline(std::cin, processName);
    std::cout << "Enter DLL file name (e.g., my_dll.dll): ";
    std::getline(std::cin, dllName);
    if (processName.empty() || dllName.empty()) {
        std::cerr << "Error: Invalid input! Process name and DLL name cannot be empty." << std::endl;
        return false;
    }
    return true;
}
int main() {
    std::string processName;
    std::string dllName;
    // ��ȡ�û�����
    if (!GetUserInput(processName, dllName)) {
        return 1;
    }
    // ���ҵ�ǰĿ¼�е� DLL �ļ�
    std::string dllPath = FindDLLInCurrentDir(dllName);
    if (dllPath.empty()) {
        std::cerr << "DLL file not found in current directory." << std::endl;
        return 1;
    }
    // ��ȡĿ����� ID
    DWORD processID = GetProcessID(processName);
    if (processID == 0) {
        std::cerr << "Failed to find target process." << std::endl;
        return 1;
    }
    // ע�� DLL
    if (InjectDLL(processID, dllPath.c_str())) {
        std::cout << "DLL injected successfully!" << std::endl;
    }
    else {
        std::cerr << "DLL injection failed." << std::endl;
    }
    return 0;
}