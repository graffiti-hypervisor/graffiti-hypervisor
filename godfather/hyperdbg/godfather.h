#ifndef _GODFATHER_H
#define _GODFATHER_H

#include "types.h"
#include "x86.h"
#include "events.h"

#define MAXPROTECTED 1024
#define MAX_PROTECTED_PROCESSES 128
#define MAX_PROTECTED_PHY 1024
#define MAX_GOD_BPS 128
#define MAX_TRACED 0x100000 	/* 2**32/2**12 */

#define READ  0x1
#define WRITE 0x2
#define EXEC  0x4

typedef Bit32u pt_status;
#define GOD_NOCHANGE     0x00000000
#define GOD_MAP          0x00000001
#define GOD_UNMAP        0x00000002
#define GOD_CHANGE_PHY   0x00000003
#define GOD_CHANGE_FLAG  0x00000004
#define GOD_IGNORE       0x00000005

typedef struct _PROTECTED {
  hvm_address cr3;
  hvm_address protected_pages[MAXPROTECTED];
  Bit32u first_free_page;
  Bit32u protected_pts;
  hvm_bool to_be_removed;
  PTE pd[1024];
} PROTECTED, *PPROTECTED;

typedef struct _PHY_PROTECTED {
  PTE old;
  hvm_address va_pte;
  hvm_address pa_pte;
  hvm_address ignore_flag;
} PHY_PROTECTED, *PPHY_PROTECTED;

typedef struct _GOD_BP {
  hvm_address phy_eip;
  Bit8u old_opcode;
} GOD_BP, *PGOD_BP;

typedef struct _TRACED_PAGE {
  Bit32u ref_count;
  Bit64u written; 		/* Stores numbers of clocks when this page was written */
  Bit64u executed; 		/* Stores numbers of clocks when this page was executed */	
                    	/* There maybe some imprecision because we take
		                     clock ticks in ring -1 not as soon as the
		                     exit occurs */
  hvm_address va;
} TRACED_PAGE, *PTRACED_PAGE;

typedef struct _VA_TRACED_PAGE {
  PTE pte;
  hvm_address address;
} VA_TRACED_PAGE, *PVA_TRACED_PAGE;

typedef struct _EXEC_FOUND_PAGE {
  Bit32u count;
  Bit32u address;
} EXEC_FOUND_PAGE, *PEXEC_FOUND_PAGE;

#define MAX_EXEC_FOUND_PTS  0x10000 

typedef struct _FREQ_INFO {
  Bit32u first_free;
  EXEC_FOUND_PAGE freq_exec[MAX_EXEC_FOUND_PTS];
} FREQ_INFO, *PFREQ_INFO;

/* Bit32u pdes; */
/* Bit32u ptes; */
/* Bit32u procs; */

hvm_status GodInit(void);
hvm_status GodAddProtectedProcess(hvm_address cr3, Bit32u *index);
void GodRemoveProtectedProcess(Bit32u index);
hvm_bool GodIsToBeRemoved(Bit32u index);
void GodSetToBeRemoved(Bit32u index);
hvm_status GodProtectAllPTs(hvm_address cr3, Bit32u index);
Bit32u GodFindProtectedProcess(hvm_address cr3);
pt_status GodCheckMapping(PPTE pold, PPTE pnew);
void GodDumpViolation(PEVENT_ARGUMENTS args);
void GodVideoLog(char *log);
void GodIncPTs(Bit32u index);
void GodDecPTs(Bit32u index);
Bit32u GodGetPTs(Bit32u index);
hvm_status GodRemoveBP(Bit32u index);
Bit32u GodFindBP(hvm_address phy_eip);
Bit32u GodAddBP(hvm_address phy_eip);
hvm_bool GodIsBlackListed(hvm_address base);
//void GodPanic(char *message);
void GodUserLogSetInfo(hvm_address cr3, hvm_address base, Bit32u row_num, Bit32u row_size);
hvm_status GodUserLog(char *log);
Bit32u GodFindTracedPage(hvm_address pa);
PTE GodGetVaTracedPage(hvm_address va);
hvm_status GodAddFreqPage(Bit32u index, hvm_address va);
/* Bit32u GodFindTracedPagePaAndVa(hvm_address pa, hvm_address va); */
hvm_status GodAddTracedPage(hvm_address pa, hvm_address va, PTE pte, Bit32u *index);
hvm_status GodRemoveTracedPage(Bit32u index);
hvm_status GodRemoveVATracedPage(hvm_address va);
void GodTracedSetWritten(Bit32u index, Bit64u written);
void GodTracedSetExecuted(Bit32u index, Bit64u executed);
hvm_address GodTracedGetPa(Bit32u index);
/* hvm_address GodTracedGetVa(Bit32u index); */
Bit64u GodTracedGetWritten(Bit32u index);
Bit64u GodTracedGetExecuted(Bit32u index);
hvm_bool GodIsPtProtected(hvm_address pt_base);
void GodSetPtProtection(hvm_address pt_base, hvm_bool protection);
#define GodSetPtProtected(pt_base) GodSetPtProtection(pt_base, TRUE)
#define GodSetPtUnprotected(pt_base) GodSetPtProtection(pt_base, FALSE)	

PPTE GodGetProtectedProcessPageDir(hvm_address cr3);
void GodDumpSomePages(void);
void GodDumpAllocInfo(void);
/* hvm_bool GodCheckProcessPresence(void); */
/* hvm_bool GodAreOverThreshold(); */

#define GodLog(fmt, ...) ComPrint((" [God] [%08x] " fmt "\n"), context.GuestContext.cr3, ## __VA_ARGS__)

#define GodPanic(log, max, fmt, ...)					\
  do {									\
    ComPrint((" [God] " fmt "\n"), ## __VA_ARGS__);			\
    vmm_memset(log, 0, 256);						\
    vmm_snprintf(log, max, ("[God] " fmt "\n"), ## __VA_ARGS__);	\
    GodUserLog(log);							\
  } while(0)
    /* __asm__ __volatile__("ud2\n");					\ */


#endif /* _GODFATHER_H */
