#define QCL_IMPL
#include "qcl.h"

int
main(void)
{
        qcl_config config = qcl_parse_file("input.qcl");

        qcl_value *v = qcl_value_get(&config, "fkjdsklfdj");

        //printf("%s\n", ((qcl_value_string *)v)->s);

        return 0;
}
