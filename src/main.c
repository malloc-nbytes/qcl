#define QCL_IMPL
#include "qcl.h"

int
main(void)
{
        qcl_config config = qcl_parse_file("input.qcl");

        qcl_value *v = qcl_value_get(&config, "f");

        printf("%d\n", ((qcl_value_bool *)v)->b);

        return 0;
}
