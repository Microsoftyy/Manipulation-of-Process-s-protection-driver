#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>

// Define IOCTL codes
#define MY_DRIVER_IOCTL_PROTECT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MY_DRIVER_IOCTL_UNPROTECT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Define PS_PROTECTION offset
constexpr auto PS_PROTECTION_OFFSET = 0x87a;

// Define structures used by driver
typedef struct _TARGET_PROCESS {
    int ProcessId;
} TARGET_PROCESS, * PTARGET_PROCESS;

typedef struct _PS_PROTECTION {
    UCHAR Level;
    UCHAR Type : 3;
    UCHAR Audit : 1;
    UCHAR Signer : 4;
} PS_PROTECTION, * PPS_PROTECTION;

// Function to check Windows version
NTSTATUS CheckWindowsVersion();

#endif // DRIVER_H