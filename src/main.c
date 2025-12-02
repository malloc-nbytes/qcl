#define QCL_IMPL
#include "qcl.h"

int
main(void)
{
        char *src = _qcl_load_file("input.qcl");
        qcl_lexer l = _qcl_lex_file("input.qcl", src);
        _qcl_lexer_dump(&l);

        return 0;
}
