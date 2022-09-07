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
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>


struct data_t {
	u32 pid;
	u32 ppid;
	int domain;
	int protocol;
	char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int syscall__socket(struct pt_regs* ctx,
	int domain,
	int type,
	int protocol)
{
	struct data_t data = {};
	struct task_struct * task;

	data.pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();
	data.ppid = task->real_parent->tgid;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	bpf_probe_read_user(&data.domain, sizeof(data.domain), &domain);
	bpf_probe_read_user(&data.protocol, sizeof(data.protocol), &protocol);
	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
}
"""

b = BPF(text = bpf_text)
socket_fnname = b.get_syscall_fnname("socket")
b.attach_kprobe(event=socket_fnname, fn_name="syscall__socket")

print("%-12s %-10s %-10s %-10s %-10s" % ("TS(ns)", "PPID", "PID", "PCMD", "CMD"))

start_ts = time.time_ns()

def get_name(pid):
	try:
		with open("/proc/%d/status" % pid) as status:
			for line in status:
				if (line.startswith("Name")):
					return bytes(line.split()[1], encoding="utf-8")
	except IOError:
		pass
	return bytes("N/A", encoding="utf-8")

def print_event(cpu, data, size):
	event = b["events"].event(data)
	if (event.domain == 16 and event.protocol == 0): # AF_NETLINK - 16 NETLINK_ROUTE - 0
		printb(b"%-12d %-10d %-10d %-10s %-10s" % (time.time_ns() - start_ts, event.ppid, event.pid, get_name(event.ppid), event.comm))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
	try:
		b.perf_buffer_poll()
	except KeyboardInterrupt:
		exit()


