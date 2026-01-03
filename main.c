#define QCL_IMPL
#include "qcl.h"

#include <stdio.h>

int
main(void)
{
        qcl_config config = qcl_parse_file("input.qcl");

        if (!qcl_ok(&config)) {
                printf("%s\n", qcl_geterr(&config));
        }

        printf("value: %s\n", ((qcl_value_string *)qcl_value_get(&config, "lst"))->s);

        return 0;
}
