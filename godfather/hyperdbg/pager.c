


#include "pager.h"
#include "gui.h"
#include "video.h"
#include "common.h"
#include "vmmstring.h"
#include "keyboard.h"
#include "debug.h"

#define PAGES 20






Bit8u  pages[PAGES][OUT_SIZE_Y][OUT_SIZE_X]; 
Bit32u current_page = 0;
Bit32u current_line = 0;
Bit32u current_visible_page = 0;

Bit32u c = LIGHT_GREEN;






static void PagerShowPage(Bit32u page);
static void PagerEditGui(void);
static void PagerRestoreGui(void);
static void PagerShowInfo(hvm_bool last);
static void PagerHideInfo(void);






void PagerReset(void)
{
  Bit32u i, ii, iii;

  
  for(ii = 0; ii < OUT_SIZE_Y; ii++) {
    vmm_strncpy(out_matrix[ii], pages[current_visible_page][ii], OUT_SIZE_X);
  }

  
  for(i = 0; i < PAGES; i++) {
    for(ii = 0; ii < OUT_SIZE_Y; ii++) {
      for(iii = 0; iii < OUT_SIZE_X; iii++)
	
	pages[i][ii][iii] = ' ';
    }
  }
  current_page = current_line = current_visible_page = 0;
}

static void PagerShowPage(Bit32u page)
{
  Bit32u ii;

  if(page >= PAGES) return;

  
  for(ii = 0; ii < OUT_SIZE_Y; ii++) 
    VideoWriteString(pages[page][ii], OUT_SIZE_X, c, OUT_START_X, OUT_START_Y+ii);

}

static void PagerEditGui()
{
  
  VideoWriteChar('=', WHITE, 3, SHELL_SIZE_Y-3);
  VideoWriteChar('[', WHITE, 4, SHELL_SIZE_Y-3);
  VideoWriteString("n: next; p: prev; q: quit", 25, LIGHT_BLUE, 5, SHELL_SIZE_Y-3);
  VideoWriteChar(']', WHITE, 30, SHELL_SIZE_Y-3);
  VideoWriteChar('=', WHITE, 31, SHELL_SIZE_Y-3);
}

static void PagerRestoreGui()
{
  Bit32u i;

  for(i = 1; i < SHELL_SIZE_X-1; i++) {
    VideoWriteChar('-', WHITE, i, SHELL_SIZE_Y-3);
  }
}

static void PagerShowInfo(hvm_bool last)
{
  Bit32u len;
  VideoWriteChar('=', WHITE, 33, SHELL_SIZE_Y-3);
  VideoWriteChar('[', WHITE, 34, SHELL_SIZE_Y-3);
  if(!last) {
    len = 5;
    VideoWriteString("START", 5, LIGHT_BLUE, 35, SHELL_SIZE_Y-3);
  }
  else {
    len = 3;
    VideoWriteString("END", 3, LIGHT_BLUE, 35, SHELL_SIZE_Y-3);
  }
  VideoWriteChar(']', WHITE, 35+len, SHELL_SIZE_Y-3);
  VideoWriteChar('=', WHITE, 36+len, SHELL_SIZE_Y-3);
}

static void PagerHideInfo()
{
  Bit32u i;
  for(i = 32; i < 42; i++) {
    VideoWriteChar('-', WHITE, i, SHELL_SIZE_Y-3);
  }
}

void PagerLoop(Bit32u color)
{
  Bit8u ch;
  hvm_bool isMouse, exitLoop = FALSE;
  Bit32u limit = 0;
  c = color;
  VideoResetOutMatrix();
  
  if(current_page > 0) {
    PagerEditGui();
    current_visible_page = 0;
    PagerShowPage(current_visible_page);
    PagerShowInfo(FALSE);

    while(1) {
      if (KeyboardReadKeystroke(&ch, FALSE, &isMouse) != HVM_STATUS_SUCCESS) {
	
	CmSleep(150);
	continue;
      }
      if (isMouse) {
	
	continue;
      }
      ch = KeyboardScancodeToKeycode(ch);

      switch(ch) {
      case 0:
	
	break;
      case 'n':
	PagerHideInfo();
	if(current_page == PAGES) limit = current_page - 1;
	else limit = current_page;
	if(current_visible_page < PAGES-1 && current_visible_page < limit)
	  PagerShowPage(++current_visible_page);
	if(current_visible_page == limit)
	  PagerShowInfo(TRUE);
	break;
      case 'p':
	PagerHideInfo();
	if(current_visible_page > 0)
	  PagerShowPage(--current_visible_page);
	if(current_visible_page == 0)
	  PagerShowInfo(FALSE);
	break;
      case 'q':
	exitLoop = TRUE;
	break;
      default:
	break; 
      }
      if(exitLoop) break;
    }
    PagerRestoreGui();
  }

  PagerReset();
  VideoRefreshOutArea(LIGHT_GREEN);
}

hvm_bool PagerAddLine(Bit8u *line)
{
  Bit32u len;

  

  
  if(current_page >= PAGES) return FALSE; 

  
  if(current_line >= OUT_SIZE_Y) return FALSE; 

  len = vmm_strlen(line);
  if(len >= OUT_SIZE_X)
    len = OUT_SIZE_X - 1;
  
  vmm_strncpy(pages[current_page][current_line], line, len);
  current_line++;
  if(current_line >= OUT_SIZE_Y) { 
    
    current_line = 0;
    
    current_page++;                
  }
  return TRUE;
}

