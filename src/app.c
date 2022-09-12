#include <stdio.h>
#include "xnet_tiny.h"

int main (void) {
    printf("tiny-tcp running...\n");
    xnet_init();
    while (1) {
        xnet_poll();
    }
}