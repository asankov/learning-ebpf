#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

int hello(struct bpf_raw_tracepoint_args *ctx) {
   u64 counter = 0;
   u64 *p;

   u64 syscall = ctx->args[1];
   p = counter_table.lookup(&syscall);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&syscall, &counter);
   return 0;
}
"""

b = BPF(text=program)

# Attach to a tracepoint that gets hit for all syscalls 
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""

    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
