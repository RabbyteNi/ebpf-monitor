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
import os

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

enum alter_type {
	ADD,
	DEL
};

struct data_t {
	u32 pid;
	u32 ppid;
	char comm[TASK_COMM_LEN];
	enum alter_type type;
};

BPF_PERF_OUTPUT(events);

int trace__fib_table_insert(struct pt_regs* ctx)
{
	struct data_t data = {};
	struct task_struct * task;

	data.pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();
	data.ppid = task->real_parent->tgid;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	data.type = ADD;
	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
}

int trace__fib_table_delete(struct pt_regs* ctx)
{
	struct data_t data = {};
	struct task_struct * task;

	data.pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();
	data.ppid = task->real_parent->tgid;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	data.type = DEL;
	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
}
"""

b = BPF(text = bpf_text)
b.attach_kprobe(event="fib_table_insert", fn_name="trace__fib_table_insert")
b.attach_kprobe(event="fib_table_delete", fn_name="trace__fib_table_delete")

print("%-12s %-10s %-10s %-10s %-10s %-10s %-10s" % ("TS(ns)", "PPID", "PID", "PCMD", "CMD", "TYPE", "NID"))

start_ts = time.time_ns()

def get_name(pid):
	try:
		with open("/proc/%d/status" % pid) as status:
			for line in status:
				if line.startswith("Name"):
					return bytes(line.split()[1], encoding="utf-8")
	except IOError:
		pass
	return bytes("N/A", encoding="utf-8")

def get_namespace_id(pid):
	link = "/proc/%d/ns/pid" % pid
	return os.readlink(link)[5:-1]

def print_event(cpu, data, size):
	event = b["events"].event(data)
	if event.type == 0:
		cmd_type = b'add'
	else:
		cmd_type = b'del'
	namespace_id = bytes(get_namespace_id(event.pid), encoding='utf-8')
	printb(b"%-12d %-10d %-10d %-10s %-10s %-10s %-10s" % (time.time_ns() - start_ts, event.ppid, event.pid, get_name(event.ppid), event.comm, cmd_type, namespace_id))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
	try:
		b.perf_buffer_poll()
	except KeyboardInterrupt:
		exit()

