#define NTDDI_VERSION NTDDI_WIN10
#include "driver.h"

NTSTATUS ProtectProcess(PTARGET_PROCESS target);
NTSTATUS UnprotectProcess(PTARGET_PROCESS target);
NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CheckWindowsVersion();

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    // Check Windows version
    status = CheckWindowsVersion();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Create symbolic link
    UNICODE_STRING devName, symLink;
    RtlInitUnicodeString(&devName, L"\\Device\\Microsoftyy");
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\Microsoftyy");
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Set IRP dispatch routines
    for (auto i = 0u; i < IRP_MJ_MAXIMUM_FUNCTION; ++i) {
        DriverObject->MajorFunction[i] = nullptr;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = nullptr;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = nullptr;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;

    return status;
}

NTSTATUS CheckWindowsVersion() {
    NTSTATUS status;
    RTL_OSVERSIONINFOW osInfo;
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);

    // Get Windows version
    status = RtlGetVersion(&osInfo);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[!] RtlGetVersion failed: 0x%08X. Refusing to load for safety.\n", status));
        return STATUS_NOT_SUPPORTED;
    }

    // Check major version and build number
    if (osInfo.dwMajorVersion != 10 || osInfo.dwBuildNumber != 19044) {
        KdPrint(("[!] Unsupported OS version.\n"));
        return STATUS_NOT_SUPPORTED;
    }

    KdPrint(("[+] Version: %lu.%lu.%lu", osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber));
    return STATUS_SUCCESS;
}

NTSTATUS ProtectProcess(PTARGET_PROCESS target) {
    NTSTATUS status;
    PEPROCESS eProcess;

    // Obtain EPROCESS for the given PID
    KdPrint(("[+] Obtaining EPROCESS for PID: %d\n", target->ProcessId));
    status = PsLookupProcessByProcessId((HANDLE)target->ProcessId, &eProcess);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[+] PsLookupProcessByProcessId failed with status: 0x%X\n", status));
        return status;
    }

    // Set protection levels to mimic SgrmBroker.exe
    PPS_PROTECTION psProtect = (PPS_PROTECTION)(((ULONG_PTR)eProcess) + PS_PROTECTION_OFFSET);
    psProtect->Level = 0x62;
    psProtect->Type = 0x2;
    psProtect->Audit = 0;
    psProtect->Signer = 0x6;

    // Dereference
    ObDereferenceObject(eProcess);

    return STATUS_SUCCESS;
}

NTSTATUS UnprotectProcess(PTARGET_PROCESS target) {
    NTSTATUS status;
    PEPROCESS eProcess;

    // Obtain EPROCESS for the given PID
    KdPrint(("[+] Obtaining EPROCESS for PID: %d\n", target->ProcessId));
    status = PsLookupProcessByProcessId((HANDLE)target->ProcessId, &eProcess);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[+] PsLookupProcessByProcessId failed with status: 0x%X\n", status));
        return status;
    }

    // Set protection levels to remove protection (set all values to 0)
    PPS_PROTECTION psProtect = (PPS_PROTECTION)(((ULONG_PTR)eProcess) + PS_PROTECTION_OFFSET);
    psProtect->Level = 0;
    psProtect->Type = 0;
    psProtect->Audit = 0;
    psProtect->Signer = 0;

    // Dereference
    ObDereferenceObject(eProcess);

    return STATUS_SUCCESS;
}

NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (!inputBuffer) {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case MY_DRIVER_IOCTL_PROTECT_PROCESS:
        status = ProtectProcess((PTARGET_PROCESS)inputBuffer);
        break;
    case MY_DRIVER_IOCTL_UNPROTECT_PROCESS:
        status = UnprotectProcess((PTARGET_PROCESS)inputBuffer);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}