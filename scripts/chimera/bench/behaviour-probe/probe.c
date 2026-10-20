/*
 * CHIMERA behaviour probe: a harmless positive control for the M5 outcome labels.
 * In a disposable analysis VM it does, once and visibly, what the labels look for:
 *   child process  - cmd.exe /c echo
 *   file drop      - %APPDATA%\chimera-probe\probe.bat (contains only "echo probe")
 *   persistence    - HKCU\...\CurrentVersion\Run "ChimeraProbe" -> that .bat
 *   network intent - DNS lookup and one HTTP GET to probe.chimera.test (answered by INetSim)
 * It reads nothing, sends no data and stays alive 30 s so it is not an early exit.
 * Build: ./build.sh
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

static void child(void)
{
    STARTUPINFOW si = {sizeof si};
    PROCESS_INFORMATION pi;
    wchar_t cmd[] = L"cmd.exe /c echo chimera-probe";
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

static void drop_and_persist(void)
{
    wchar_t dir[MAX_PATH], path[MAX_PATH];
    HKEY key;
    if (!GetEnvironmentVariableW(L"APPDATA", dir, MAX_PATH))
        return;
    wcscat(dir, L"\\chimera-probe");
    CreateDirectoryW(dir, NULL);
    swprintf(path, MAX_PATH, L"%ls\\probe.bat", dir);
    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD n;
        WriteFile(f, "echo probe\r\n", 12, &n, NULL);
        CloseHandle(f);
    }
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                      KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        RegSetValueExW(key, L"ChimeraProbe", 0, REG_SZ, (const BYTE *)path,
                       (DWORD)((wcslen(path) + 1) * sizeof(wchar_t)));
        RegCloseKey(key);
    }
}

static void network(void)
{
    WSADATA wsa;
    struct addrinfo *res = NULL;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
        if (getaddrinfo("probe.chimera.test", "80", NULL, &res) == 0)
            freeaddrinfo(res);
        WSACleanup();
    }
    HINTERNET s = WinHttpOpen(L"chimera-probe/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!s)
        return;
    HINTERNET c = WinHttpConnect(s, L"probe.chimera.test", 80, 0);
    HINTERNET r = c ? WinHttpOpenRequest(c, L"GET", L"/check", NULL, NULL, NULL, 0) : NULL;
    if (r && WinHttpSendRequest(r, NULL, 0, NULL, 0, 0, 0))
        WinHttpReceiveResponse(r, NULL);
    if (r) WinHttpCloseHandle(r);
    if (c) WinHttpCloseHandle(c);
    WinHttpCloseHandle(s);
}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show)
{
    child();
    drop_and_persist();
    network();
    Sleep(30000);
    return 0;
}
