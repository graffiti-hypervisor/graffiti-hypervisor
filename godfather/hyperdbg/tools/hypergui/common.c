


#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

#include "common.h"

extern HWND g_hWndEdit;

void ShowError(const char *msg, ...) {
  va_list ap;
  char tmp[1024];
  
  va_start(ap, msg);
  _vsnprintf(tmp, sizeof(tmp), msg, ap);
  va_end(ap);

  MessageBox(NULL, tmp, "Error", MB_ICONEXCLAMATION | MB_OK);
}

void LogMessage(const char *fmt, ...)
{
  va_list ap;
  char newdata[1024], *data;
  SYSTEMTIME lt;
  LRESULT n;

  GetLocalTime(&lt);
  _snprintf(newdata, sizeof(newdata), "[%02d-%02d-%04d %02d:%02d:%02d.%03d] ",
	   lt.wDay, lt.wMonth, lt.wYear, lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);

  va_start(ap, fmt);
  _vsnprintf((char*)newdata + strlen(newdata), 
	    sizeof(newdata) - strlen(newdata) - 1, 
	    fmt, ap);
  va_end(ap);

  strncat(newdata, "\r\r\n", sizeof(newdata));

  n = SendMessage(g_hWndEdit, EM_GETLIMITTEXT, 0, 0);
  data = (char*) malloc(n + strlen(newdata));
  if(!data) {
    ShowError("Dynamic allocation error.");
    return;
  }

  
  SendMessage(g_hWndEdit, WM_GETTEXT, n, (LPARAM) data);

  
  strncat(data, newdata, (n + strlen(newdata)));

  
  SendMessage(g_hWndEdit, WM_SETTEXT, 0, (LPARAM) data); 
}
