prefix ?= /usr
includedir = $(prefix)/include
HEADER = qcl.h

.PHONY: all install uninstall

all: $(HEADER)
	printf '#define QCL_IMPL\n#include "qcl.h"\nint main(void) {return 0;}' \
	| cc -x c - -o main -O2 -Wextra -Wall

install: $(HEADER)
	install -d $(DESTDIR)$(includedir)
	install -m 0644 $(HEADER) $(DESTDIR)$(includedir)/$(HEADER)

uninstall:
	rm -f $(DESTDIR)$(includedir)/$(HEADER)
