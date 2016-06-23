


#include "loader.h"
#include "common.h"

static char driver_filename[MAX_PATH];

DWORD LoaderLoadDriver()
{
  DWORD x;
  SC_HANDLE hSCM, hService;

  debug("[*] Loading driver: %s", driver_filename);

  hSCM = hService = NULL;
  x = ERROR_SUCCESS;

  hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (!hSCM) {
    x = GetLastError();
    ShowError("Unable to open SCManager (error #%d).", (unsigned int) x);
    goto end;
  }

  hService = CreateService(hSCM, HYPERDBG_SERVICE_NAME, "HyperDbg",
			   SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER,
			   SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, driver_filename,
			   NULL, NULL, NULL, NULL, NULL);

  if (!hService) {
    x = GetLastError();
    ShowError("Unable to create driver service (error #%d).", (unsigned int) x);
    goto end;
  }

  if (!StartService(hService, 0, NULL)) {
    SERVICE_STATUS ss;

    x = GetLastError();

    ShowError("Unable to start driver service (error #%d).", (unsigned int) x);

    
    hService = OpenService(hSCM, HYPERDBG_SERVICE_NAME, SERVICE_START | DELETE | SERVICE_STOP);
    ControlService(hService, SERVICE_CONTROL_STOP, &ss);
    DeleteService(hService);
    goto end;
  }

 end:
  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);
  return x;
}

DWORD LoaderRemoveDriver()
{
  DWORD x;
  SC_HANDLE hSCM, hService;
  SERVICE_STATUS ss;

  hSCM = hService = NULL;
  x = ERROR_SUCCESS;

  hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (!hSCM) {
    x = GetLastError();
    ShowError("Unable to open SCManager (error #%d).", (unsigned int) x);
    goto end;
  }

  hService = OpenService(hSCM, HYPERDBG_SERVICE_NAME, SERVICE_START | DELETE | SERVICE_STOP);
  ControlService(hService, SERVICE_CONTROL_STOP, &ss);
  DeleteService(hService);

 end:
  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);
  return x;  
}

BOOL LoaderInit()
{
  BOOL b;

  
  LoaderRemoveDriver();

  
  GetSystemDirectory(driver_filename, sizeof(driver_filename) - sizeof(HYPERDBG_DRIVER_FILENAME));
  strncat(driver_filename, "\\", sizeof(driver_filename));
  strncat(driver_filename, HYPERDBG_DRIVER_FILENAME, sizeof(driver_filename));

  
  
  b = CopyFile(HYPERDBG_DRIVER_FILENAME, driver_filename, FALSE);
  if (!b) {
    GetSystemDirectory(driver_filename, sizeof(driver_filename));
    ShowError("Unable to copy driver file. "
	      "Check that '%s' exists in the current directory and that you have write access to Windows system directory "
	      "('%s')\n", HYPERDBG_DRIVER_FILENAME, driver_filename);
    return FALSE;
  }

  return TRUE;
}

BOOL LoaderFini()
{
  if(!driver_filename[0]) {
    
    GetSystemDirectory(driver_filename, sizeof(driver_filename) - sizeof(HYPERDBG_DRIVER_FILENAME));
    strncat(driver_filename, "\\", sizeof(driver_filename));
    strncat(driver_filename, HYPERDBG_DRIVER_FILENAME, sizeof(driver_filename));
  }

  DeleteFile(driver_filename);
  return TRUE;
}
