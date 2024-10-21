#include <Windows.h>
#include <cstdio>
#include <cstring>
#include "driver.h"

enum class Action {
    Protect,
    Unprotect
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s <PID> <protect|unprotect>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);
    Action action;

    if (_stricmp(argv[2], "protect") == 0) {
        action = Action::Protect;
    }
    else if (_stricmp(argv[2], "unprotect") == 0) {
        action = Action::Unprotect;
    }
    else {
        printf("Invalid action. Use 'protect' or 'unprotect'.\n");
        return 1;
    }

    // Open handle to the driver
    HANDLE hDriver = CreateFile(L"\\\\.\\Microsoftyy", GENERIC_READ | GENERIC_WRITE, 0,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("Failed to open handle to driver\n");
        return 1;
    }

    // Prepare the target process structure
    TARGET_PROCESS target = { pid };

    // Prepare the IOCTL code based on the action
    DWORD ioctlCode;
    if (action == Action::Protect) {
        ioctlCode = MY_DRIVER_IOCTL_PROTECT_PROCESS;
    }
    else {
        ioctlCode = MY_DRIVER_IOCTL_UNPROTECT_PROCESS;
    }

    // Send IOCTL request to the driver
    DWORD bytesReturned;
    BOOL success = DeviceIoControl(hDriver, ioctlCode, &target, sizeof(target), nullptr, 0, &bytesReturned, nullptr);

    if (!success) {
        printf("DeviceIoControl failed with error: %lu\n", GetLastError());
        CloseHandle(hDriver);
        return 1;
    }

    printf("Success\n");

    CloseHandle(hDriver);
    return 0;
}