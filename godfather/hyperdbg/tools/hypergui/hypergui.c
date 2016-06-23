


#include <stdio.h>
#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include "loader.h"
#include "common.h"
#include "../../hyperdbg.h"





#define PACKVERSION(major,minor) MAKELONG(minor,major)

#define HYPERGUI_ICON_ID        128
#define HYPERGUI_ICON_MESSAGE   WM_APP+1
#define HYPERGUI_MENU_OPEN      1
#define HYPERGUI_MENU_INSTALL   2
#define HYPERGUI_MENU_REMOVE    3
#define HYPERGUI_MENU_EXIT      4
#define HYPERGUI_BUTTON_COPY    5





static const char g_szClassName[] = "hyperguiWindowClass";
static BOOL g_installed = FALSE;
static HWND g_hWndMain; 


HWND g_hWndEdit;





static int RunConsole(LPSTR ptr);
static int RunGUI(HINSTANCE hInstance);

static BOOL InitControls(HINSTANCE hInstance);
static int WndManageTrayIcon(HWND hWnd, DWORD dwAction);
static int WndCreateClass(HINSTANCE hInstance, WNDCLASSEX *pwc);
static DWORD GetDllVersion(LPCTSTR lpszDllName);
static void ShowContextMenu(HWND hWnd);

static int ConsoleCommandInstall();
static int ConsoleCommandRemove();
static int ConsoleCommandInfo();
static int ConsoleCommandHelp();

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);





static void ShowContextMenu(HWND hWnd)
{
  POINT pt;
  HMENU hMenu;

  GetCursorPos(&pt);
  hMenu = CreatePopupMenu();

  if(hMenu) {
    InsertMenu(hMenu, -1, MF_BYPOSITION, HYPERGUI_MENU_OPEN, "Open");
    InsertMenu(hMenu, -1, MF_BYPOSITION | (g_installed ? MF_GRAYED : 0), HYPERGUI_MENU_INSTALL, "Install");
    InsertMenu(hMenu, -1, MF_BYPOSITION | (g_installed ? 0 : MF_GRAYED), HYPERGUI_MENU_REMOVE, "Remove");
    InsertMenu(hMenu, -1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
    InsertMenu(hMenu, -1, MF_BYPOSITION, HYPERGUI_MENU_EXIT, "Exit");

    
    SetForegroundWindow(hWnd);

    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN, pt.x, pt.y, 0, hWnd, NULL );
    DestroyMenu(hMenu);
  }
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
  switch (msg) {
  case HYPERGUI_ICON_MESSAGE:
    
    switch (lParam) {
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_CONTEXTMENU:
      ShowContextMenu(hWnd);
      break;
    case WM_LBUTTONDBLCLK:
      ShowWindow(hWnd, SW_SHOW);
      break;
    }

    break;

  case WM_DESTROY:
    WndManageTrayIcon(hWnd, NIM_DELETE);
    PostQuitMessage(0);
    break;

  case WM_COMMAND:
    if(HIWORD(wParam) == BN_CLICKED) {
      switch(LOWORD(wParam)) {
      case HYPERGUI_MENU_OPEN:
	ShowWindow(hWnd, SW_SHOW);
	break;
      case HYPERGUI_MENU_INSTALL:
	
	if(MessageBox(hWnd, "Ready to slip into the matrix?", "Are you sure?", 
		      MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES) {
	  LogMessage("Loading driver...");
	  if (LoaderLoadDriver() != ERROR_SUCCESS) {
	    
	    LogMessage("Driver loading failed -- cleaning up");
	    LoaderRemoveDriver();
	  } else {
	    LogMessage("Driver successfully loaded");
	    MessageBox(NULL, "Driver successfully loaded! Press F12 to start debugging.", "Success", MB_ICONINFORMATION | MB_OK);
	    g_installed = TRUE;
	  }
	}
	break;

      case HYPERGUI_MENU_REMOVE:
	
	if(MessageBox(hWnd, "Do you really want to remove HyperDbg?", "Are you sure?", 
		      MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES) {
	  LogMessage("Removing driver...");
	  LoaderRemoveDriver();
	  g_installed = FALSE;
	  LogMessage("Driver removed");
	}
	break;

      case HYPERGUI_MENU_EXIT:
	
	if(MessageBox(hWnd, "Are you sure you want to exit?", "Are you sure?", 
		      MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES) {
	  DestroyWindow(hWnd);
	}
	break;

      case HYPERGUI_BUTTON_COPY: {
	DWORD n;
	HGLOBAL hglbCopy; 
	LPTSTR  lptstrCopy; 

	n = SendMessage(g_hWndEdit, EM_GETLIMITTEXT, 0, 0);
	hglbCopy = GlobalAlloc(GMEM_MOVEABLE, n);
        if (hglbCopy == NULL)
	  break;

        lptstrCopy = GlobalLock(hglbCopy);
	SendMessage(g_hWndEdit, WM_GETTEXT, n, (LPARAM) lptstrCopy);
        GlobalUnlock(hglbCopy);

	OpenClipboard(NULL);
	EmptyClipboard();
	SetClipboardData(CF_TEXT, hglbCopy);
	CloseClipboard();

	GlobalFree(hglbCopy);
	break;
      }

      default:
	break;
      }
    }
    break;

  case WM_SYSCOMMAND:
    if((wParam & 0xFFF0) == SC_MINIMIZE || (wParam & 0xFFF0) == SC_CLOSE) {
      ShowWindow(hWnd, SW_HIDE);
      return 1;
    }
    

  default:
    return DefWindowProc(hWnd, msg, wParam, lParam);
  }

  return 0;
}

static int WndCreateClass(HINSTANCE hInstance, WNDCLASSEX *pwc)
{
  pwc->cbSize        = sizeof(WNDCLASSEX);
  pwc->style         = 0;
  pwc->lpfnWndProc   = WndProc;
  pwc->cbClsExtra    = 0;
  pwc->cbWndExtra    = 0;
  pwc->hInstance     = hInstance;
  pwc->hIcon         = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(HYPERGUI_ICON_ID));

  if(!pwc->hIcon) {
    
    pwc->hIcon       = LoadIcon(NULL, IDI_APPLICATION);
  }

  pwc->hCursor       = LoadCursor(NULL, IDC_ARROW);
  pwc->hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
  pwc->lpszMenuName  = NULL;
  pwc->lpszClassName = g_szClassName;
  pwc->hIconSm       = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(HYPERGUI_ICON_ID));

  if(!pwc->hIconSm) {
    
    pwc->hIconSm     = LoadIcon(NULL, IDI_APPLICATION);
  }

  if(!RegisterClassEx(pwc)) {
    ShowError("Window registration failed!");
    return FALSE;
  }

  return TRUE;
}

static DWORD GetDllVersion(LPCTSTR lpszDllName)
{
  HINSTANCE hinstDll;
  DWORD dwVersion = 0;

  
  hinstDll = LoadLibrary(lpszDllName);
  
  if(hinstDll) {
    DLLGETVERSIONPROC pDllGetVersion;
    pDllGetVersion = (DLLGETVERSIONPROC)GetProcAddress(hinstDll, "DllGetVersion");

    

    if(pDllGetVersion) {
      DLLVERSIONINFO dvi;
      HRESULT hr;

      ZeroMemory(&dvi, sizeof(dvi));
      dvi.cbSize = sizeof(dvi);

      hr = (*pDllGetVersion)(&dvi);

      if(SUCCEEDED(hr)) {
	dwVersion = PACKVERSION(dvi.dwMajorVersion, dvi.dwMinorVersion);
      }
    }

    FreeLibrary(hinstDll);
  }
  return dwVersion;
}

static int WndManageTrayIcon(HWND hWnd, DWORD dwAction)
{
  NOTIFYICONDATA niData;
  ULONGLONG ullVersion;

  ZeroMemory(&niData,sizeof(NOTIFYICONDATA));
  ullVersion = GetDllVersion("Shell32.dll");

  if(ullVersion >= PACKVERSION(6,0))
    niData.cbSize = sizeof(NOTIFYICONDATA);
  else if(ullVersion >= PACKVERSION(5,0))
    niData.cbSize = NOTIFYICONDATA_V2_SIZE;
  else 
    niData.cbSize = NOTIFYICONDATA_V1_SIZE;

  niData.uID = HYPERGUI_ICON_ID;
  niData.hWnd = hWnd;		

  switch (dwAction) {
  case NIM_ADD:
    
    niData.uCallbackMessage = HYPERGUI_ICON_MESSAGE;
    niData.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(HYPERGUI_ICON_ID));
    if(!niData.hIcon) {
      
      LoadIcon(NULL, IDI_APPLICATION);
    }
    strncpy(niData.szTip, "HyperGUI", sizeof(niData.szTip));

    niData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    break;

  case NIM_DELETE:
    
    break;

  default:
    
    return FALSE;
  }

  Shell_NotifyIcon(dwAction, &niData);

  return TRUE;
}

static BOOL InitControls(HINSTANCE hInstance)
{
  WNDCLASSEX wc;
  HWND hWndButton;

  
  if(!WndCreateClass(hInstance, &wc)) {
    ShowError("Window registration failed!");
    return FALSE;
  }

  
  g_hWndMain = CreateWindowEx(WS_EX_CLIENTEDGE, g_szClassName, "HyperGUI", 
			      WS_MINIMIZEBOX | WS_SYSMENU | WS_CAPTION,
			      CW_USEDEFAULT, CW_USEDEFAULT, 600, 400,
			      NULL, NULL, hInstance, NULL);

  if(g_hWndMain == NULL) {
    ShowError("Window creation failed!");
    return FALSE;
  }

  
  hWndButton = CreateWindow("BUTTON", "Copy to Clipboard", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
			    20, 320, 130, 40, g_hWndMain, (HMENU) HYPERGUI_BUTTON_COPY, hInstance, NULL);

  
  g_hWndEdit = CreateWindow("EDIT", NULL, 
			    WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | EM_FMTLINES | ES_READONLY | ES_AUTOVSCROLL | ES_LOWERCASE, 
			    20, 10, 550, 300, g_hWndMain, NULL, hInstance, NULL);

  
  WndManageTrayIcon(g_hWndMain, NIM_ADD);

  return TRUE;
}

static int ConsoleCommandHelp()
{
  MessageBox(NULL, 
	     "Help:\n"
	     "/h shows this help message\n"
	     "/i install HyperDbg without GUI\n"
	     "/r uninstall HyperDbg\n"
	     "/v print version and info\n", 
	     "Help", MB_ICONINFORMATION | MB_OK);

  return TRUE;
}

static int ConsoleCommandInfo()
{
  MessageBox(NULL, 
	     "HyperDbg " HYPERDBG_VERSION "\n"
	     HYPERDBG_URL "\n"
	     "Coded by: martignlo, roby, joystick\n",
	     "Info", MB_ICONINFORMATION | MB_OK);

  return TRUE;
}

static int ConsoleCommandInstall()
{
  
  if (!LoaderInit()) {
    ShowError("Initialization failed");
    DestroyWindow(g_hWndMain);
    return FALSE;
  }

  if (LoaderLoadDriver() != ERROR_SUCCESS) {
    
    ShowError("Driver loading failed -- cleaning up!");
    LoaderRemoveDriver();
    return FALSE;
  }

  MessageBox(NULL, "Driver successfully loaded! Press F12 to start debugging.", "Success", MB_ICONINFORMATION | MB_OK);
  return TRUE;
}

static int ConsoleCommandRemove()
{
  if(LoaderRemoveDriver() != ERROR_SUCCESS) {
    ShowError("Driver unloading failed!");
    return FALSE;
  }

  
  if (!LoaderFini()) {
    ShowError("Finalization failed");
    return FALSE;
  }

  MessageBox(NULL, "Driver successfully unloaded!", "Success", MB_ICONINFORMATION | MB_OK);
  return TRUE;
}


static int RunConsole(LPSTR ptr)
{
  int r;

  ptr++;

  switch(ptr[0]) {
  case 'h':
    r = ConsoleCommandHelp();
    break;
  case 'i':
    r = ConsoleCommandInstall();
    break;
  case 'r':
    r = ConsoleCommandRemove();
    break;
  case 'v':
    r = ConsoleCommandInfo();
    break;
  default:
    ShowError("Unrecognized option: '%s'", ptr);
    r = FALSE;
    break;
  }

  
  return r;
}


static int RunGUI(HINSTANCE hInstance)
{
  MSG msg;

  
  if (!LoaderInit()) {
    ShowError("Initialization failed");
    DestroyWindow(g_hWndMain);
    return FALSE;
  }

  
  if(!InitControls(hInstance)) {
    ShowError("Initialization failed");
    return FALSE;
  }

  LogMessage("Initialization completed");

  
  while(GetMessage(&msg, NULL, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }

  
  if (!LoaderFini()) {
    ShowError("Finalization failed");
    return FALSE;
  }

  LogMessage("Finalization completed");

  return msg.wParam;
}

int __cdecl main(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
  LPSTR ptr;
  int r;

  
  ptr = GetCommandLine();
  while(*ptr != ' ') ptr++; 
  while(*ptr == ' ') ptr++; 

  
  if(*ptr == '/') {
    r = RunConsole(ptr);
  } else {
    r = RunGUI(hInstance);
  }

  return r;
}
