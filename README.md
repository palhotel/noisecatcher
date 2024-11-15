NoiseCatcher
======================

NoiseCatcher is tool like Linux OS Noise, based on eBPF and IDLE schedule class monitor threads on each CPU.
This repository will open source the platform department code, without the communication with BMC, 
while a helpful mock server is provided to verfiy, and update to suit for any envrioments.

We provide some params like -d: debug mode, print the outputs to screen. and -m: mock mode, send data to a mock service instead of BMC.

# Get Started

1. compile the monitor: `make`
2. run the mockserver: `sudo python3 mockusbbmc.py`
2. run eBPF tracers, and check the `/sys/fs/bpf` to see the pinned bpf maps, and shutdown the `nc_thread.py`, make sure this thread are running after the monitor threads bootstrap, because it will fetch the pid of monitors.
3. run monitor thread on each core, you are free to test it for run only one instance, for example, use `sudo taskset -c 0 ./noisecatcher -d -m`, and be free to write a script, or use the splited window terminals like terminators is good idea.
4. run the bpf tracers, for example: `sudo python3 nc_irq.py -d`
5. use any tool to inspect the noise.db, which is a SQLite database.
