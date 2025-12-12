#include <stdio.h>
#include <assert.h>
#include <string.h>

#if HAVE_STDARG_H
#  include <stdarg.h>
#  define VA_START(a, f)        va_start(a, f)
#else
#  if HAVE_VARARGS_H
#    include <varargs.h>
#    define VA_START(a, f)      va_start(a)
#  endif
#endif
#ifndef VA_START
#  error no variadic api
#endif

  /* Define these two macros to check the effect of missing 
     vprintf and _doprnt

     #define HAVE_VPRINTF 0
     #define HAVE_DOPRNT 0 */

#if HAVE_VPRINTF
#  define VFPRINTF(file, fmt, ap)        vfprintf(file, fmt, ap)
#else
#  if HAVE_DOPRNT
#    define VFPRINTF(file, fmt, ap)      _doprnt(fmt, ap, file)
#  else
#    error no vfprintf or _doprnt
#  endif
#endif

#include "mydiag.h"

void
#if HAVE_STDARG_H
my_error (char *file, int line, const char *format, ...)
#else
my_error (file, line, format, va_alist)
     char *file;
     int line;
     const char *format;
     va_dcl
#endif
{
  va_list ap;

  assert(file);
  assert(format);

  VA_START(ap, format);
  fprintf(stderr, "%s:%d: ERROR: ", file, line);
  (void)VFPRINTF(stderr, format, ap);
  va_end (ap);
  if (*format) 
    {
      format += strlen(format);
      if (format[-1] != '\n')
	(void)fputc('\n', stderr);
    }

  fflush(stderr);
  return;
}

void
#if HAVE_STDARG_H
my_warning (char *file, int line, const char *format, ...)
#else
my_warning (file, line, format, va_alist)
     char *file;
     int line;
     const char *format;
     va_dcl
#endif
{
  va_list ap;

  assert(file);
  assert(format);

  VA_START(ap, format);
  fprintf(stderr, "%s:%d: WARNING: ", file, line);
  (void)VFPRINTF(stderr, format, ap);
  va_end (ap);
  if (*format) 
    {
      format += strlen(format);
      if (format[-1] != '\n')
	(void)fputc('\n', stderr);
    }

  fflush(stderr);
  return;
}

void
#if HAVE_STDARG_H
my_debug (char *file, int line, const char *format, ...)
#else
my_debug (file, line, format, va_alist)
     char *file;
     int line;
     const char *format;
     va_dcl
#endif
{
  va_list ap;

  assert(file);
  assert(format);

  VA_START(ap, format);
  fprintf(stderr, "%s:%d: DEBUG: ", file, line);
  (void)VFPRINTF(stderr, format, ap); 
  va_end (ap);
  if (*format) 
    {
      format += strlen(format);
      if (format[-1] != '\n')
	(void)fputc('\n', stderr);
    }

  fflush(stderr);
  return;
}
