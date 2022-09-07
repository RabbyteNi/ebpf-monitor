from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import bcc.utils as utils
import argparse
import re
import time
import pwd
from collections import defaultdict
from time import strftime

bpf_text = """
#define ARGSIZE 128
#define MAXARG 20

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

enum event_type {
	EVENT_ARG,
	EVENT_RET
};

struct data_t {
	u32 pid;
	u32 ppid;
	char comm[TASK_COMM_LEN];
	char argv[ARGSIZE];
	enum event_type type;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
	bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
	events.perf_submit(ctx, data, sizeof(struct data_t));
	return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{

    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();

    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
            break;
    }
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();

    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# initialize BPF
b = BPF(text = bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

# Headers
print("%-12s %-10s %-10s %-10s %-10s" % ("TS(ns)", "PPID", "PCMD", "PID", "CMD"))

start_ts = time.time_ns()
argv = defaultdict(list)

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

regex_pattern = "ip route (add|del)"

def print_event(cpu, data, size):
    event = b["events"].event(data)
    if event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        if (re.search(bytes(regex_pattern, encoding='utf-8'), b' '.join(argv[event.pid]))):
            argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
            printb(b"%-12d %-10d %-10s %-10d %-10s" % (time.time_ns() - start_ts, event.ppid, event.comm, event.pid, argv_text))
        try:
            del(argv[event.pid])
        except Exception:
            pass

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
