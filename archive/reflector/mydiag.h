#ifndef MYDIAG_H
#define MYDIAG_H 

#if __STDC__
#  ifndef NOPROTOS
#    define PARAMS(args)      args
#  endif
#endif
#ifndef PARAMS
#  define PARAMS(args)        ()
#endif

extern void my_error PARAMS((char *file, int line, const char *format, ...));
extern void my_warning PARAMS((char *file, int line, const char *format, ...));
extern void my_debug PARAMS((char *file, int line, const char *format, ...));

#endif /* MYDIAG_H */
