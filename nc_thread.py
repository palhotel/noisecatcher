from bcc import BPF
import subprocess
import os
import psutil
import time
import ctypes
import argparse

parser = argparse.ArgumentParser(description="Noise Catcher")
parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
args = parser.parse_args()

# Path to pin the BPF map
PIN_PATH = "/sys/fs/bpf/thread_store"

def get_pids(process_name):
    pids = []
    try:
        result = subprocess.run(['ps', '-ef'], stdout=subprocess.PIPE)
        lines = result.stdout.decode('utf-8').split('\n')
        for line in lines:
            if process_name in line:
                parts = line.split()
                pid = int(parts[1])
                pids.append(pid)
    except Exception as e:
        print(f"Error getting PIDs: {e}")
    return pids

def get_cpu_for_pid(pid):
    try:
        proc = psutil.Process(pid)
        return proc.cpu_num()
    except psutil.NoSuchProcess:
        return None

num_cpus = os.cpu_count()
process_name = "noisecatcher"
pids = get_pids(process_name)
cpu_pid_array = [0] * num_cpus

for pid in pids:
    cpu_num = get_cpu_for_pid(pid)
    if cpu_num is not None and cpu_num < num_cpus:
        cpu_pid_array[cpu_num] = pid

pid_array_str = ",".join(map(str, cpu_pid_array))
print(pid_array_str)

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_CPUS __NUM_CPUS__

struct data_t {
    u64 count;
    u64 duration;
    u64 updatetime;
    u64 maxtime;
};

struct sched_trace_event {
    u64 __unused__;
    char prev_comm[TASK_COMM_LEN];
    u32 prev_pid;
    u32 prev_prio;
    u64 prev_state;
    char next_comm[TASK_COMM_LEN];
    u32 next_pid;
    u32 next_prio;
};

//BPF_HASH(thread_store, u32, struct data_t);
BPF_TABLE_PINNED("percpu_hash", u32, struct data_t, thread_store, 256, "/sys/fs/bpf/thread_store");
BPF_ARRAY(pids, u32, MAX_CPUS);

int trace_sched_switch(struct sched_trace_event *ctx) {
    u64 delta;
    struct data_t data = {};

    u64 ts = bpf_ktime_get_ns();
    u32 cpu_id = bpf_get_smp_processor_id();
    
    struct data_t *entry = thread_store.lookup_or_try_init(&cpu_id, &(struct data_t){0, 0, 0, 0});
    if (!entry) {
        return 0;
    }
    if (entry->updatetime == 0) {
        entry->updatetime = ts;
        return 0;
    }

    u32 *pid_ptr = pids.lookup(&cpu_id);
    
    if (pid_ptr == 0){
        return 0; // No PID assigned to this CPU
    }
    u32 pid = *pid_ptr;

    if (pid == 0) {
        return 0;
    }

    if(ctx->next_pid == ctx->prev_pid){
        return 0;
    }
    
    if (pid == ctx->next_pid) {
        entry->updatetime = ts;
    } else if (pid == ctx->prev_pid) {
        delta = ts - entry->updatetime;
        entry->count++;
        entry->duration += delta;
        entry->updatetime = ts;
        if (entry->maxtime < delta) {
            entry->maxtime = delta;
        }
    }

    return 0;
}
"""

bpf_text = bpf_text.replace("__NUM_CPUS__", str(num_cpus))


# Check if the map is already pinned
if not os.path.exists(PIN_PATH):
    # Load BPF program and pin the map
    b = BPF(text=bpf_text)
else:
    # Load BPF program without creating the map
    b = BPF(text=bpf_text, cflags=["-DPINNED"])
    # Attach the existing pinned map
    b["thread_store"] = b.get_table("thread_store", PIN_PATH)

b.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_sched_switch")
# 初始化 BPF_ARRAY
pids = b.get_table("pids")
for i in range(num_cpus):
    pids[ctypes.c_int(i)] = ctypes.c_uint(cpu_pid_array[i])

if args.debug:
    print("%-8s %-6s %-16s %-16s %-16s" % ("TIME", "CPU", "COUNT", "DURATION(ns)", "UPDATETIME(ns)"))

try:
    while True:
        time.sleep(1)
        if args.debug:
            # b.trace_print();
            current_time = time.strftime("%H:%M:%S")
            for k, v_array in b.get_table("thread_store").items():
                for cpu_id, v in enumerate(v_array):
                    print("%-8s %-6d %-6d %-16d %-16d %-16d" % (current_time, k.value, cpu_id, v.count, v.duration, v.updatetime))
except KeyboardInterrupt:
    print("Exiting...")
finally:
    b.cleanup()
