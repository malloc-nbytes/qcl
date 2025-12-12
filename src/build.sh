#!/bin/bash

set -xe

echo '#define QCL_IMPL
#include "qcl.h"
int main(void) {
return 0;
}' | cc -x c - -o main -ggdb -O0

cc -o main main.c
