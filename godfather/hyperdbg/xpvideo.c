






#ifdef XPVIDEO

#include <ddk/ntddk.h>
#include <ntdef.h>
#include <Ntddvdeo.h>

#include "types.h"
#include "debug.h"


extern POBJECT_TYPE IoDriverObjectType; 
extern NTKERNELAPI NTSTATUS ObReferenceObjectByName(  
  IN PUNICODE_STRING ObjectPath,  
  IN ULONG Attributes,
  IN PACCESS_STATE PassedAccessState OPTIONAL,  
  IN ACCESS_MASK DesiredAccess OPTIONAL,
  IN POBJECT_TYPE ObjectType OPTIONAL, 
  IN KPROCESSOR_MODE AccessMode,  
  IN OUT PVOID ParseContext OPTIONAL,  
  OUT PVOID *ObjectPtr  
  );

NTSTATUS XpVideoFindDisplayMiniportDriverName(PUNICODE_STRING name);
NTSTATUS XpVideoGetDeviceObject(PUNICODE_STRING driverName, PDEVICE_OBJECT *deviceObject);
NTSTATUS XpVideoGetVideoMemoryAddress(PDEVICE_OBJECT device, PHYSICAL_ADDRESS *vidMemPhys, ULONG *size);
NTSTATUS XpVideoGetVideoModeInformation(PDEVICE_OBJECT device, VIDEO_MODE_INFORMATION *vidModeinfo); 
NTSTATUS XpVideoDoDeviceIoControl(PDEVICE_OBJECT device, ULONG ioctl, PVOID input, ULONG inputlen, PVOID output, ULONG outputlen);
ULONG    XpVideoGetRealStride(ULONG width, ULONG stride);
hvm_bool XpVideoIsDriverVgaSave(PUNICODE_STRING driverName);

hvm_status XpVideoGetWindowsXPDisplayData(hvm_address *addr, Bit32u *framebuffer_size, Bit32u *width, Bit32u *height, Bit32u *stride) {
  UNICODE_STRING driverName;
  PVOID stringBuf;
  NTSTATUS status;
  VIDEO_MODE_INFORMATION vidModeInfo;
  PDEVICE_OBJECT deviceObject;
  PHYSICAL_ADDRESS physAddr;
  ULONG length;
  hvm_bool is_vgasave;

  
  stringBuf = ExAllocatePoolWithTag(NonPagedPool, 1024, 'lnoj');
  if(!stringBuf) {
    GuestLog("[xpvideo] can't allocate memory!");
    return HVM_STATUS_UNSUCCESSFUL;
  }

  RtlInitEmptyUnicodeString(&driverName, (PWCHAR)stringBuf, 1024);

  
  status = XpVideoFindDisplayMiniportDriverName(&driverName);
  if(!NT_SUCCESS(status)) {
    ExFreePool(stringBuf);
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  is_vgasave = XpVideoIsDriverVgaSave(&driverName);
  if(is_vgasave) {
    GuestLog("[xpvideo] Driver is standard VGA");
  } else {
    GuestLog("[xpvideo] Driver is NOT standard VGA");
  }

  
  status = XpVideoGetDeviceObject(&driverName, &deviceObject);
  if(!NT_SUCCESS(status)) {
    ExFreePool(stringBuf);
    return HVM_STATUS_UNSUCCESSFUL;
  }
  
  
  ExFreePool(stringBuf);

  
  status = XpVideoGetVideoMemoryAddress(deviceObject, &physAddr, framebuffer_size);
  if(!NT_SUCCESS(status)) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  *addr = physAddr.LowPart;

  
  status = XpVideoDoDeviceIoControl(
    deviceObject,
    IOCTL_VIDEO_QUERY_CURRENT_MODE,
    NULL,
    0,
    &vidModeInfo,
    sizeof(VIDEO_MODE_INFORMATION));

  if(!NT_SUCCESS(status)) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  *height = vidModeInfo.VisScreenHeight;
  *width = vidModeInfo.VisScreenWidth;

  
  if(is_vgasave) {
    *stride = *width;
  } else {
    *stride = XpVideoGetRealStride(*width, vidModeInfo.ScreenStride / (vidModeInfo.BitsPerPlane / 8));
  }

  GuestLog("[xpvideo] using resolution %d x %d, stride %d", *width, *height, *stride);
  
  
  *framebuffer_size = *height * *stride * (vidModeInfo.BitsPerPlane / 8);

  return HVM_STATUS_SUCCESS;
}


NTSTATUS XpVideoFindDisplayMiniportDriverName(PUNICODE_STRING name) {
  OBJECT_ATTRIBUTES keyObject;
  UNICODE_STRING keyName;
  UNICODE_STRING keyValueName;
  HANDLE keyHandle;
  UCHAR *valueBuffer;

  NTSTATUS status;
  ULONG resultLen;
  KEY_VALUE_FULL_INFORMATION *valueInfo;
  UNICODE_STRING valueString;
  USHORT len;

  
  RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\Hardware\\DeviceMap\\Video");
  InitializeObjectAttributes(&keyObject, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
  status = ZwOpenKey(&keyHandle, KEY_QUERY_VALUE, &keyObject);
  if(!NT_SUCCESS(status)) {
    GuestLog("[xpvideo] can't open key %ws", keyName.Buffer);
    return status;
  }

  valueBuffer = (UCHAR *)ExAllocatePoolWithTag(NonPagedPool, 4096, 'lnoj');
  if(!valueBuffer) {
    GuestLog("[xpvideo] can't allocate registry value buffer");
    ZwClose(keyHandle);
    return STATUS_UNSUCCESSFUL;
  }

  RtlInitUnicodeString(&keyValueName, L"\\Device\\Video0");
  status = ZwQueryValueKey(keyHandle, &keyValueName, KeyValueFullInformation, valueBuffer, 4096, &resultLen);
  if(!NT_SUCCESS(status)) {
    GuestLog("[xpvideo] cant query value %ws", keyValueName.Buffer);
    ExFreePool(valueBuffer);
    ZwClose(keyHandle);
    return status;
  }

  
  ZwClose(keyHandle);

  
  valueInfo = (KEY_VALUE_FULL_INFORMATION *)valueBuffer;
  RtlInitUnicodeString(&valueString, (PCWSTR)(valueBuffer + valueInfo->DataOffset));

  
  valueString.MaximumLength = (USHORT)(4096 - (valueInfo->DataOffset + valueInfo->DataLength));

  
  len = valueString.Length - 1;
  while(len > 0 && valueString.Buffer[len/2] != '\\')
    len-=2;

  
  valueString.Length = len;
  RtlAppendUnicodeToString(&valueString, L"\\Video");

  GuestLog("[xpvideo] video key value is %ws", valueString.Buffer);

  
  RtlZeroMemory(&keyObject, sizeof(keyObject));
  RtlInitUnicodeString(&keyName, valueString.Buffer);
  InitializeObjectAttributes(&keyObject, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
  status = ZwOpenKey(&keyHandle, KEY_QUERY_VALUE, &keyObject);
  if(!NT_SUCCESS(status)) {
    GuestLog("[xpvideo] can't open key %ws", keyName.Buffer);
    ExFreePool(valueBuffer);
    return status;
  }

  RtlInitUnicodeString(&keyValueName, L"Service");
  status = ZwQueryValueKey(keyHandle, &keyValueName, KeyValueFullInformation, valueBuffer, 4096, &resultLen);
  if(!NT_SUCCESS(status)) {
    GuestLog("[xpvideo] cant query value %ws", keyValueName.Buffer);
    ExFreePool(valueBuffer);
    ZwClose(keyHandle);
    return status;
  }

  valueInfo = (KEY_VALUE_FULL_INFORMATION *)valueBuffer;
  RtlInitUnicodeString(&valueString, (PCWSTR)(valueBuffer + valueInfo->DataOffset));

  GuestLog("[xpvideo] \\Device\\Video0 service name is '%ws'", valueString.Buffer);

  RtlAppendUnicodeToString(name, L"\\Driver\\");
  RtlAppendUnicodeToString(name, valueString.Buffer);

  GuestLog("[xpvideo] full driver path is %ws", name->Buffer);

  ExFreePool(valueBuffer);
  ZwClose(keyHandle);
  return STATUS_SUCCESS;
}


NTSTATUS XpVideoDoDeviceIoControl(PDEVICE_OBJECT device, ULONG ioctl, PVOID input, ULONG inputlen, PVOID output, ULONG outputlen) {
  PIRP irp;
  KEVENT event;
  IO_STATUS_BLOCK iostatus;
  NTSTATUS status;

  RtlZeroMemory(output, outputlen);
  KeInitializeEvent(&event, NotificationEvent, FALSE);

  
  irp = IoBuildDeviceIoControlRequest(
    ioctl,
    device,
    input,
    inputlen,
    output,
    outputlen,
    FALSE,
    &event,
    &iostatus);

  if (irp == NULL) {
    GuestLog("[xpvideo] can't create IRP!");
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  status = IoCallDriver(device, irp);

  if (status == STATUS_PENDING) {
    KeWaitForSingleObject(
      &event,
      Executive,
      KernelMode,
      FALSE,
      NULL);
    status = iostatus.Status;
  }

  if(!NT_SUCCESS(status)) {
    GuestLog("[xpvideo] DeviceIoControl call failed");
  }

  return status;
}

NTSTATUS XpVideoGetVideoMemoryAddress(PDEVICE_OBJECT device, PHYSICAL_ADDRESS *vidMemPhys, ULONG *size) {
  VIDEO_MEMORY vidMem;
  VIDEO_MEMORY_INFORMATION vidMemInfo;
  PIRP irp;
  KEVENT event;
  IO_STATUS_BLOCK iostatus;
  NTSTATUS status;
  NTSTATUS orig_status;

  
  status = XpVideoDoDeviceIoControl(
    device,
    IOCTL_VIDEO_MAP_VIDEO_MEMORY,
    &vidMem,
    sizeof(VIDEO_MEMORY),
    &vidMemInfo,
    sizeof(VIDEO_MEMORY_INFORMATION));

  
  if(NT_SUCCESS(status)) {
    *vidMemPhys = MmGetPhysicalAddress(vidMemInfo.FrameBufferBase);
    *size = vidMemInfo.FrameBufferLength;
    GuestLog("[xpvideo] Framebuffer physical address 0x%.8x, size %x", vidMemPhys, *size);
  }

  
  vidMem.RequestedVirtualAddress = vidMemInfo.FrameBufferBase;
  XpVideoDoDeviceIoControl(
    device,
    IOCTL_VIDEO_UNMAP_VIDEO_MEMORY,
    &vidMem,
    sizeof(VIDEO_MEMORY),
    NULL,
    0);

  return status;
}

NTSTATUS XpVideoGetDeviceObject(PUNICODE_STRING driverName, PDEVICE_OBJECT *deviceObject) {
  NTSTATUS status;
  PDRIVER_OBJECT driverObject;
  PDEVICE_OBJECT tmpDeviceObject;

  
  status = ObReferenceObjectByName(driverName, OBJ_CASE_INSENSITIVE, NULL, 0, IoDriverObjectType, KernelMode, NULL, (PVOID *)&driverObject);
  if(status != STATUS_SUCCESS) {
    GuestLog("[xpvideo] Can't find object %ws", driverName->Buffer);
    return status;
  }

  
  tmpDeviceObject = driverObject->DeviceObject;
  while(tmpDeviceObject->NextDevice != NULL) tmpDeviceObject = tmpDeviceObject->NextDevice;

  *deviceObject = tmpDeviceObject;
  return status;
}

ULONG XpVideoGetRealStride(ULONG width, ULONG stride) {
  
  if(width != stride) return stride;

  if(width == 1440) return 2048; 
  if(width == 1680) return 1792; 

  return width;
}


hvm_bool XpVideoIsDriverVgaSave(PUNICODE_STRING driverName) {
  UNICODE_STRING vgaSave;
  LONG ret;

  RtlInitUnicodeString(&vgaSave, L"\\Driver\\VgaSave");
  ret = RtlCompareUnicodeString(driverName, &vgaSave, TRUE);

  if(ret == 0) {
    return TRUE;
  } else {
    return FALSE;
  }
}

#endif
