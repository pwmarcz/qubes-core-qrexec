#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libqrexec-utils.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1)
        return 0;

    bool strip_username = data[0] != 0;

    char *cmdline = malloc(size);
    memcpy(cmdline, data + 1, size - 1);
    cmdline[size - 1] = 0;

    struct qrexec_parsed_command cmd;
    if (parse_qubes_rpc_command(cmdline, strip_username, &cmd) < 0) {
        free(cmdline);
        return 0;
    }

    printf("username: %s\n", cmd.username);
    printf("cmd: %s\n", cmd.cmd);
    printf("service_descriptor: %.*s\n",
           (int) cmd.service_descriptor_length,
           cmd.service_descriptor);
    free(cmdline);
    return 0;
}
