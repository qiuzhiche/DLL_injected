#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <shlwapi.h>  // 用于 PathAppend
#pragma comment(lib, "shlwapi.lib")  // 链接 shlwapi.lib
void PrintError(const std::string& msg) {
    DWORD errCode = GetLastError();
    std::cerr << msg << " Error Code: " << errCode << " (" << errCode << ")" << std::endl;
}
// 注入 DLL
bool InjectDLL(DWORD processID, const char* dllPath) {
    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        PrintError("Failed to open target process");
        return false;
    }
    // 在目标进程中分配内存
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteMemory == NULL) {
        PrintError("Failed to allocate memory in target process");
        CloseHandle(hProcess);
        return false;
    }
    // 将 DLL 路径写入目标进程内存
    if (!WriteProcessMemory(hProcess, pRemoteMemory, (LPVOID)dllPath, strlen(dllPath) + 1, NULL)) {
        PrintError("Failed to write to target process memory");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    // 获取 LoadLibraryA 函数地址
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        PrintError("Failed to get address of LoadLibraryA");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    // 创建远程线程，执行 LoadLibraryA
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMemory, 0, NULL);
    if (hRemoteThread == NULL) {
        PrintError("Failed to create remote thread");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    // 等待线程执行完成
    WaitForSingleObject(hRemoteThread, INFINITE);
    // 清理资源
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);
    return true;
}
// 获取当前程序所在目录
std::string GetCurrentDir() {
    char buffer[MAX_PATH];
    if (GetModuleFileNameA(NULL, buffer, MAX_PATH)) {
        PathRemoveFileSpecA(buffer);  // 去掉文件名，只保留目录
        return std::string(buffer);
    }
    return "";
}
// 获取进程 ID
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
            // 使用 wcscmp 进行宽字符比较
            if (wcscmp(pe.szExeFile, std::wstring(processName.begin(), processName.end()).c_str()) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}
// 查找 DLL 文件
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
    return "";  // 返回空字符串表示未找到 DLL 文件
}
// 获取命令行参数并验证输入
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
    // 获取用户输入
    if (!GetUserInput(processName, dllName)) {
        return 1;
    }
    // 查找当前目录中的 DLL 文件
    std::string dllPath = FindDLLInCurrentDir(dllName);
    if (dllPath.empty()) {
        std::cerr << "DLL file not found in current directory." << std::endl;
        return 1;
    }
    // 获取目标进程 ID
    DWORD processID = GetProcessID(processName);
    if (processID == 0) {
        std::cerr << "Failed to find target process." << std::endl;
        return 1;
    }
    // 注入 DLL
    if (InjectDLL(processID, dllPath.c_str())) {
        std::cout << "DLL injected successfully!" << std::endl;
    }
    else {
        std::cerr << "DLL injection failed." << std::endl;
    }
    return 0;
}