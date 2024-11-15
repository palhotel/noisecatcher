from bcc import BPF
import time
import os
import argparse

parser = argparse.ArgumentParser(description="Noise Catcher")
parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
args = parser.parse_args()

# Path to pin the BPF map
PIN_PATH = "/sys/fs/bpf/nmi_store"

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 count;
    u64 duration;
    u64 updatetime;
    u64 maxtime;
};

//PF_HASH(nmi_store, u32, struct data_t);
BPF_TABLE_PINNED("percpu_hash", u32, struct data_t, nmi_store, 256, "/sys/fs/bpf/nmi_store");

struct nmi_trace_event {
    u64 __unused__;
    void *handler;
    s64 delta_ns;
    int handled;
};

int trace_nmi_handler(struct nmi_trace_event *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u32 cpu_id = bpf_get_smp_processor_id();
    s64 delta_ns = ctx->delta_ns;

    struct data_t *entry = nmi_store.lookup_or_try_init(&cpu_id, &(struct data_t){0, 0, 0, 0});
    if (entry) {
        entry->updatetime = ts;
        entry->count++;
        entry->duration += delta_ns;
        if (entry->maxtime < delta_ns) {
            entry->maxtime = delta_ns;
        }
    }
    return 0;
}
"""

# Check if the map is already pinned
if not os.path.exists(PIN_PATH):
    # Load BPF program and pin the map
    b = BPF(text=bpf_text)
else:
    # Load BPF program without creating the map
    b = BPF(text=bpf_text, cflags=["-DPINNED"])
    # Attach the existing pinned map
    b["nmi_store"] = b.get_table("nmi_store", PIN_PATH)

# Attach BPF program to tracepoint
b.attach_tracepoint(tp="nmi:nmi_handler", fn_name="trace_nmi_handler")

if args.debug:
    # Print header
    print("%-8s %-6s %-16s %-16s %-16s" % ("TIME", "CPU", "COUNT", "DURATION(ns)", "UPDATETIME(ns)"))

# Output loop
try:
    while True:
        time.sleep(1)

        if args.debug:
            # Get current time
            current_time = time.strftime("%H:%M:%S")

            # Print map contents
            for k, v_array in b.get_table("nmi_store").items():
                for cpu_id, v in enumerate(v_array):
                    print("%-8s %-6d %-6d %-16d %-16d %-16d" % (current_time, k.value, cpu_id, v.count, v.duration, v.updatetime))
except KeyboardInterrupt:
    print("Exiting...")
