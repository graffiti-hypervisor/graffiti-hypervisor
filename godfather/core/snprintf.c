



#define HAVE_STRING_H
#define HAVE_CTYPE_H
#define HAVE_STDLIB_H
#define HAVE_LONG_LONG

#ifdef GUEST_WINDOWS
 #include <stdint.h>
 #ifdef HAVE_STRING_H
  #include <string.h>
 #endif

 #ifdef HAVE_STRINGS_H
  #include <strings.h>
 #endif
 #ifdef HAVE_CTYPE_H
  #include <ctype.h>
 #endif
 #include <sys/types.h>
 #include <stdarg.h>
 #ifdef HAVE_STDLIB_H
  #include <stdlib.h>
 #endif

#elif defined GUEST_LINUX
 #ifdef HAVE_STRING_H
  #include <linux/string.h>
 #endif

 #ifdef HAVE_STRINGS_H

 #endif
 #ifdef HAVE_CTYPE_H
  #include <linux/ctype.h>
 #endif
  #include <linux/types.h>
  #include <linux/kernel.h>

 #ifdef HAVE_STDLIB_H

 #endif
#endif


#if defined(HAVE_SNPRINTF) && defined(HAVE_VSNPRINTF) && defined(HAVE_C99_VSNPRINTF)

# include <stdio.h>
 
void dummy_snprintf (
  void
)
{
}
#else

# ifdef HAVE_LONG_LONG
#  define LLONG long long
# else
#  define LLONG long
# endif

# ifdef isdigit
#  undef isdigit
# endif
# define isdigit(c) ((c) >= '0' && (c) <= '9')

static size_t dopr (char *buffer, size_t maxlen, const char *format, va_list args);
static void fmtstr (char *buffer, size_t * currlen, size_t maxlen, char *value, int flags, int min, int max);
static void fmtint (char *buffer, size_t * currlen, size_t maxlen, long long value, int base, int min, int max, int flags);
static void dopr_outch (char *buffer, size_t * currlen, size_t maxlen, char c);




# define DP_S_DEFAULT 0
# define DP_S_FLAGS   1
# define DP_S_MIN     2
# define DP_S_DOT     3
# define DP_S_MAX     4
# define DP_S_MOD     5
# define DP_S_CONV    6
# define DP_S_DONE    7


# define DP_F_MINUS      (1 << 0)
# define DP_F_PLUS       (1 << 1)
# define DP_F_SPACE      (1 << 2)
# define DP_F_NUM        (1 << 3)
# define DP_F_ZERO       (1 << 4)
# define DP_F_UP         (1 << 5)
# define DP_F_UNSIGNED   (1 << 6)


# define DP_C_SHORT   1
# define DP_C_LONG    2
# define DP_C_LDOUBLE 3
# define DP_C_LLONG   4

# define char_to_int(p) ((p)- '0')
# ifndef MAX
#  define MAX(p,q) (((p) >= (q)) ? (p) : (q))
# endif

static size_t dopr (char *buffer, size_t maxlen, const char *format, va_list args)
{
  char ch;
  LLONG value;
  char *strvalue;
  int min;
  int max;
  int state;
  int flags;
  int cflags;
  size_t currlen;

  state = DP_S_DEFAULT;
  currlen = flags = cflags = min = 0;
  max = -1;
  ch = *format++;

  while (state != DP_S_DONE) {
    if (ch == '\0')
      state = DP_S_DONE;

    switch (state) {
    case DP_S_DEFAULT:
      if (ch == '%')
        state = DP_S_FLAGS;
      else
        dopr_outch (buffer, &currlen, maxlen, ch);
      ch = *format++;
      break;
    case DP_S_FLAGS:
      switch (ch) {
      case '-':
        flags |= DP_F_MINUS;
        ch = *format++;
        break;
      case '+':
        flags |= DP_F_PLUS;
        ch = *format++;
        break;
      case ' ':
        flags |= DP_F_SPACE;
        ch = *format++;
        break;
      case '#':
        flags |= DP_F_NUM;
        ch = *format++;
        break;
      case '0':
        flags |= DP_F_ZERO;
        ch = *format++;
        break;
      default:
        state = DP_S_MIN;
        break;
      }
      break;
    case DP_S_MIN:
      if (isdigit ((unsigned char) ch)) {
        min = 10 * min + char_to_int (ch);
        ch = *format++;
      } else if (ch == '*') {
        min = va_arg (args, int
        );
        ch = *format++;
        state = DP_S_DOT;
      } else {
        state = DP_S_DOT;
      }
      break;
    case DP_S_DOT:
      if (ch == '.') {
        state = DP_S_MAX;
        ch = *format++;
      } else {
        state = DP_S_MOD;
      }
      break;
    case DP_S_MAX:
      if (isdigit ((unsigned char) ch)) {
        if (max < 0)
          max = 0;
        max = 10 * max + char_to_int (ch);
        ch = *format++;
      } else if (ch == '*') {
        max = va_arg (args, int
        );
        ch = *format++;
        state = DP_S_MOD;
      } else {
        state = DP_S_MOD;
      }
      break;
    case DP_S_MOD:
      switch (ch) {
      case 'h':
        cflags = DP_C_SHORT;
        ch = *format++;
        break;
      case 'l':
        cflags = DP_C_LONG;
        ch = *format++;
        if (ch == 'l') {        
          cflags = DP_C_LLONG;
          ch = *format++;
        }
        break;
      case 'L':
        cflags = DP_C_LDOUBLE;
        ch = *format++;
        break;
      default:
        break;
      }
      state = DP_S_CONV;
      break;
    case DP_S_CONV:
      switch (ch) {
      case 'd':
      case 'i':
        if (cflags == DP_C_SHORT)
          value = va_arg (args, int
          );
        else if (cflags == DP_C_LONG)
          value = va_arg (args, long int
          );
        else if (cflags == DP_C_LLONG)
          value = va_arg (args, LLONG);
        else
          value = va_arg (args, int
          );
        fmtint (buffer, &currlen, maxlen, value, 10, min, max, flags);
        break;
      case 'o':
        flags |= DP_F_UNSIGNED;
        if (cflags == DP_C_SHORT)
          value = va_arg (args, unsigned int
          );
        else if (cflags == DP_C_LONG)
          value = (long) va_arg (args, unsigned long int
          );
        else if (cflags == DP_C_LLONG)
          value = (long) va_arg (args, unsigned LLONG
          );
        else
          value = (long) va_arg (args, unsigned int
          );
        fmtint (buffer, &currlen, maxlen, value, 8, min, max, flags);
        break;
      case 'u':
        flags |= DP_F_UNSIGNED;
        if (cflags == DP_C_SHORT)
          value = va_arg (args, unsigned int
          );
        else if (cflags == DP_C_LONG)
          value = (long) va_arg (args, unsigned long int
          );
        else if (cflags == DP_C_LLONG)
          value = (LLONG) va_arg (args, unsigned LLONG
          );
        else
          value = (long) va_arg (args, unsigned int
          );
        fmtint (buffer, &currlen, maxlen, value, 10, min, max, flags);
        break;
      case 'X':
        flags |= DP_F_UP;
      case 'x':
        flags |= DP_F_UNSIGNED;
        if (cflags == DP_C_SHORT)
          value = va_arg (args, unsigned int
          );
        else if (cflags == DP_C_LONG)
          value = (long) va_arg (args, unsigned long int
          );
        else if (cflags == DP_C_LLONG)
          value = (LLONG) va_arg (args, unsigned LLONG
          );
        else
          value = (long) va_arg (args, unsigned int
          );
        fmtint (buffer, &currlen, maxlen, value, 16, min, max, flags);
        break;
      case 'f':
        break;
      case 'E':
        flags |= DP_F_UP;
      case 'e':
        break;
      case 'G':
        flags |= DP_F_UP;
      case 'g':
        break;
      case 'c':
        
        dopr_outch (buffer, &currlen, maxlen, va_arg (args, int));
        break;
      case 's':
        strvalue = va_arg (args, char*);
        if (max == -1) {
          max = strlen (strvalue);
        }
        if (min > 0 && max >= 0 && min > max)
          max = min;
        fmtstr (buffer, &currlen, maxlen, strvalue, flags, min, max);
        break;
      case 'p':
        flags |= DP_F_UNSIGNED | DP_F_UP;
        strvalue = va_arg (args, void*);
        
        fmtint (buffer, &currlen, maxlen, (unsigned long) strvalue, 16, min, max, flags);
        break;
      case 'n':
        if (cflags == DP_C_SHORT) {
          short int *num;
          num = va_arg (args, short int*);
          *num = (short int) currlen;
        } else if (cflags == DP_C_LONG) {
          long int *num;
          num = va_arg (args, long int*);
          *num = (long int) currlen;
        } else if (cflags == DP_C_LLONG) {
          LLONG *num;
          num = va_arg (args, LLONG *);
          *num = (LLONG) currlen;
        } else {
          int *num;
          num = va_arg (args, int*);
          *num = currlen;
        }
        break;
      case '%':
        dopr_outch(buffer, &currlen, maxlen, ch);
        break;
      case 'w':
        
        ch = *format++;
        break;
      default:
        
        break;
      }
      ch = *format++;
      state = DP_S_DEFAULT;
      flags = cflags = min = 0;
      max = -1;
      break;
    case DP_S_DONE:
      break;
    default:
      
      break;                    
    }
  }
  if (maxlen != 0) {
    if (currlen < maxlen - 1)
      buffer[currlen] = '\0';
    else if (maxlen > 0)
      buffer[maxlen - 1] = '\0';
  }

  return currlen;
}

static void fmtstr (
  char *buffer,
  size_t * currlen,
  size_t maxlen,
  char *value,
  int flags,
  int min,
  int max
)
{
  int padlen, strln;            
  int cnt = 0;

# ifdef DEBUG_SNPRINTF
  printf("fmtstr min=%d max=%d s=[%s]\n", min, max, value);
# endif
  if (value == 0) {
    value = "<NULL>";
  }

  for (strln = 0; value[strln]; ++strln);       
  padlen = min - strln;
  if (padlen < 0)
    padlen = 0;
  if (flags & DP_F_MINUS)
    padlen = -padlen;           

  while ((padlen > 0) && (cnt < max)) {
    dopr_outch (buffer, currlen, maxlen, ' ');
    --padlen;
    ++cnt;
  }
  while (*value && (cnt < max)) {
    dopr_outch (buffer, currlen, maxlen, *value++);
    ++cnt;
  }
  while ((padlen < 0) && (cnt < max)) {
    dopr_outch (buffer, currlen, maxlen, ' ');
    ++padlen;
    ++cnt;
  }
}



static void fmtint (
  char *buffer,
  size_t * currlen,
  size_t maxlen,
  long long value,
  int base,
  int min,
  int max,
  int flags
)
{

  int signvalue = 0;
  unsigned long long uvalue;
  char convert[20];
  int place = 0;
  int spadlen = 0;              
  int zpadlen = 0;              
  int caps = 0;

  if (max < 0)
    max = 0;

  uvalue = (unsigned long long) value;


  if (!(flags & DP_F_UNSIGNED)) {
    if (value < 0) {
      signvalue = '-';
      uvalue = (unsigned long long) -value;
    } else {
      if (flags & DP_F_PLUS)    
        signvalue = '+';
      else if (flags & DP_F_SPACE)
        signvalue = ' ';
    }
  }

  if (flags & DP_F_UP)
    caps = 1;                   
  do {
#ifdef GUEST_LINUX
    
    convert[place++] = (caps ? "0123456789ABCDEF" : "0123456789abcdef")[((unsigned long)uvalue) % (unsigned) base];
    uvalue = (((unsigned long)uvalue) / (unsigned) base);
#elif defined GUEST_WINDOWS
    convert[place++] = (caps ? "0123456789ABCDEF" : "0123456789abcdef")[uvalue % (unsigned) base];    
    uvalue = (uvalue / (unsigned) base);
#endif
  } while (uvalue && (place < 20));
  if (place == 20)
    place--;
  convert[place] = 0;

  zpadlen = max - place;
  spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
  if (zpadlen < 0)
    zpadlen = 0;
  if (spadlen < 0)
    spadlen = 0;
  if (flags & DP_F_ZERO) {
    zpadlen = MAX (zpadlen, spadlen);
    spadlen = 0;
  }
  if (flags & DP_F_MINUS)
    spadlen = -spadlen;         

# ifdef DEBUG_SNPRINTF
  
# endif

  
  while (spadlen > 0) {
    dopr_outch (buffer, currlen, maxlen, ' ');
    --spadlen;
  }

  
  if (signvalue)
    dopr_outch (buffer, currlen, maxlen, (char) signvalue);

  
  if (zpadlen > 0) {
    while (zpadlen > 0) {
      dopr_outch (buffer, currlen, maxlen, '0');
      --zpadlen;
    }
  }

  
  while (place > 0)
    dopr_outch (buffer, currlen, maxlen, convert[--place]);

  
  while (spadlen < 0) {
    dopr_outch (buffer, currlen, maxlen, ' ');
    ++spadlen;
  }
}

static void dopr_outch (char *buffer, size_t * currlen, size_t maxlen, char c)
{
  if (*currlen < maxlen) {
    buffer[(*currlen)] = c;
  }
  (*currlen)++;
}

# if !defined(HAVE_VSNPRINTF) || !defined(HAVE_C99_VSNPRINTF)
int vmm_vsnprintf (char *str, size_t count, const char *fmt, va_list args)
{
  return dopr (str, count, fmt, args);
}
# endif

# if !defined(HAVE_SNPRINTF) || !defined(HAVE_C99_VSNPRINTF)
int vmm_snprintf (char *str, size_t count, const char *fmt, ...)
{
  size_t ret;
  va_list ap;

  va_start (ap, fmt);
  ret = vmm_vsnprintf (str, count, fmt, ap);
  va_end (ap);
  return ret;
}
# endif

#endif
