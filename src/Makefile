main: *.h
	printf '#define QCL_IMPL\n#include "qcl.h"\nint main(void) {return 0;}' \
	| cc -x c - -o main -O2 -Wextra -Wall
