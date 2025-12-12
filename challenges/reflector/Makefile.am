AM_CFLAGS = -Wall
#AM_CFLAGS = -Wall -static -DDEBUG

noinst_HEADERS = reflector.h mydiag.h

bin_PROGRAMS = reflector

reflector_SOURCES = reflector.c mydiag.c mydiag.h reflector.h

dist-hook:
	rm -f  $(distdir)/*~
