#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>

#define ELEMS(arr) (sizeof (arr)/sizeof *(arr))

static int const allowed[] = {
    #include "allowed.c"
};

uint32_t const statime_kill_thread  = SCMP_ACT_KILL;
uint32_t const statime_kill_process = SCMP_ACT_KILL_PROCESS;
uint32_t const statime_trap         = SCMP_ACT_TRAP;
uint32_t const statime_err          = SCMP_ACT_ERRNO(EPERM);
uint32_t const statime_log          = SCMP_ACT_LOG;

int statime_sandbox(uint32_t def_action) {
    switch (def_action) {
        case SCMP_ACT_KILL:
        case SCMP_ACT_KILL_PROCESS:
        case SCMP_ACT_TRAP:
        case SCMP_ACT_ERRNO(EPERM):
        case SCMP_ACT_LOG:
            break;
        default:
            return -EINVAL;
    }

    scmp_filter_ctx ctx = seccomp_init(def_action);
    if (!ctx)
        return -ENOMEM;

    for (size_t i = 0; i < ELEMS(allowed); i++) {
        int syscall_nr = allowed[i];
        int result = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_nr, 0);
        if (result < 0)
            return seccomp_release(ctx), result;
    }

    int result = seccomp_load(ctx);
    if (result < 0)
        return seccomp_release(ctx), result;

    seccomp_release(ctx);
    return 0;
}
