# Chapter 3: Anatomy of an eBPF Program

## Notes

### eBPF Virtual Machine

A virtual machine (software implementation of a computer) that executes the eBPF bytecode.

The code is JIT-compiled (Just-In-Time).
In the past, it used to be interpreted, but that was changed to JIT compilation for performance and security reasons.

eBPF bytecode consists of a set of instructions that act on (virtual) eBPF registers.

### eBPF Registers

The eBPF virtual machine has 10 general-purpose registers numbered 0 to 9.
As an eBPF program is executed, values get stored in these registers to keep track of the state of the program.

The eBPF registers are implemented in software, and they can be seen enumerated in the [Linux kernel source code](https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/bpf.h).

The context argument of an eBPF function is loaded into Register 1.
The return value of the function is loaded into Register 0.
The arguments of the functions are placed in Registers 1 through 5.
Additionally, Register 10 is used as a stack frame pointers (it can be read, but not written).

### eBPF Instructions

Instructions to be executed.

Defined in the [Linux kernel source code](https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/bpf.h).

### Inspecting an eBPF program

Can be done via the `file` utility or `llvm-objdump`

### Loading an eBPF program

Can be done via `bpftool`

## Links

- [ ] [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [ ] [BPF tips & tricks: the guide to bpf_trace_printk() and bpf_printk()](https://nakryiko.com/posts/bpf-tips-printk/)
- [ ] [Unofficial eBPF spec by Iovisor](https://github.com/iovisor/bpf-docs/blob/master/eBPF.md)
- [ ] [eBPF standart documentation](https://github.com/ietf-wg-bpf/ebpf-docs)
- [ ] [Features of bpftool: the thread of tips and examples to work with eBPF objects](https://qmonnet.github.io/whirl-offload/2021/09/23/bpftool-features-thread/)
- [ ] [Assembly within! BPF tail calls on x86 and ARM](https://blog.cloudflare.com/assembly-within-bpf-tail-calls-on-x86-and-arm)

- [LLVM](https://llvm.org/)

## Exercises

### Exercise 1

Try using `ip link` commands like the following to attach and detach the XDP program:

```console
ip link set dev eth0 xdp obj hello.bpf.o sec xdp
ip link set dev eth0 xdp off
```

**Solution:** I tried it and it worked correctly.

```console
$ sudo ip link set dev wlp59s0 xdp obj hello.bpf.o sec xdp
$ ip link
...
2: wlp59s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc noqueue state UP mode DORMANT group default qlen 1000
    link/ether 18:1d:ea:20:c8:3f brd ff:ff:ff:ff:ff:ff
    prog/xdp id 284
...
$ sudo ip link set dev wlp59s0 xdp off
$ ip link
...
2: wlp59s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000
    link/ether 18:1d:ea:20:c8:3f brd ff:ff:ff:ff:ff:ff
...
```

### Exercise 2

Run any of the BCC examples from Chapter 2.
While the program is running, use a second terminal window to inspect the loaded program using bpftool.
Here’s an example of what I saw by running the [hello-map.py](../chapter2/hello-map.py) example:

```console
$ bpftool prog show name hello
197: kprobe name hello tag ba73a317e9480a37 gpl
 loaded_at 2022-08-22T08:46:22+0000 uid 0
 xlated 296B jited 328B memlock 4096B map_ids 65
 btf_id 179
 pids hello-map.py(2785)
```

You can also use `bpftool prog dump` commands to see the bytecode and machine code versions of those programs.

**Solution:** This is what I see when I run the programs:

- [hello.py](../chapter2/hello.py)

  ```console
  $ sudo bpftool prog show
  ...
  319: kprobe  name hello  tag f1db4e564ad5219a  gpl
    loaded_at 2024-02-29T12:43:21+0200  uid 0
    xlated 104B  jited 68B  memlock 4096B
    btf_id 421
    pids python3(94847)

  $ sudo bpftool prog dump xlated name hello
    int hello(void * ctx):
    ; int hello(void *ctx) {
    0: (b7) r1 = 560229490
    ; ({ char _fmt[] = "Hello World!"; bpf_trace_printk_(_fmt, sizeof(_fmt)); });
    1: (63) *(u32 *)(r10 -8) = r1
    2: (18) r1 = 0x6f57206f6c6c6548
    4: (7b) *(u64 *)(r10 -16) = r1
    5: (b7) r1 = 0
    6: (73) *(u8 *)(r10 -4) = r1
    7: (bf) r1 = r10
    ;
    8: (07) r1 += -16
    ; ({ char _fmt[] = "Hello World!"; bpf_trace_printk_(_fmt, sizeof(_fmt)); });
    9: (b7) r2 = 13
    10: (85) call bpf_trace_printk#-108416
    ; return 0;
    11: (b7) r0 = 0
    12: (95) exit

  $ sudo bpftool prog dump jited name hello
    int hello(void * ctx):
    bpf_prog_f1db4e564ad5219a_hello:
    ; int hello(void *ctx) {
    0: nopl (%rax,%rax)
    5: nop
    7: pushq %rbp
    8: movq %rsp, %rbp
    b: subq $16, %rsp
    12: movl $560229490, %edi
    ; ({ char _fmt[] = "Hello World!"; bpf_trace_printk_(_fmt, sizeof(_fmt)); });
    17: movl %edi, -8(%rbp)
    1a: movabsq $8022916924116329800, %rdi
    24: movq %rdi, -16(%rbp)
    28: xorl %edi, %edi
    2a: movb %dil, -4(%rbp)
    2e: movq %rbp, %rdi
    ;
    31: addq $-16, %rdi
    ; ({ char _fmt[] = "Hello World!"; bpf_trace_printk_(_fmt, sizeof(_fmt)); });
    35: movl $13, %esi
    3a: callq 0xffffffffcaa89228
    ; return 0;
    3f: xorl %eax, %eax
    41: leave
    42: retq
    43: int3

  ```

- [hello-map.py](../chapter2/hello-map.py)

  ```console
  $ sudo bpftool prog show
  ...
  293: kprobe  name hello  tag b1f8218e038bd6c4  gpl
      loaded_at 2024-02-29T12:33:59+0200  uid 0
      xlated 232B  jited 134B  memlock 4096B  map_ids 96
      btf_id 389
      pids python3(93198)

  $ sudo bpftool prog dump xlated name hello
    int hello(void * ctx):
    ; int hello(void *ctx) {
    0: (b7) r1 = 0
    ; u64 counter = 0;
    1: (7b) *(u64 *)(r10 -16) = r1
    ; uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    2: (85) call bpf_get_current_uid_gid#235520
    ; uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    3: (67) r0 <<= 32
    4: (77) r0 >>= 32
    ; uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    5: (7b) *(u64 *)(r10 -8) = r0
    ; p = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -1), &uid);
    6: (18) r1 = map[id:96]
    8: (bf) r2 = r10
    ;
    9: (07) r2 += -8
    ; p = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -1), &uid);
    10: (85) call __htab_map_lookup_elem#267104
    11: (15) if r0 == 0x0 goto pc+1
    12: (07) r0 += 56
    13: (b7) r1 = 1
    ; if (p != 0) {
    14: (15) if r0 == 0x0 goto pc+3
    ; counter = *p;
    15: (79) r1 = *(u64 *)(r0 +0)
    ; counter = *p;
    16: (7b) *(u64 *)(r10 -16) = r1
    ; }
    17: (07) r1 += 1
    ; counter++;
    18: (7b) *(u64 *)(r10 -16) = r1
    ; bpf_map_update_elem((void *)bpf_pseudo_fd(1, -1), &uid, &counter, BPF_ANY);
    19: (18) r1 = map[id:96]
    21: (bf) r2 = r10
    ;
    22: (07) r2 += -8
    23: (bf) r3 = r10
    24: (07) r3 += -16
    ; bpf_map_update_elem((void *)bpf_pseudo_fd(1, -1), &uid, &counter, BPF_ANY);
    25: (b7) r4 = 0
    26: (85) call htab_map_update_elem#278848
    ; return 0;
    27: (b7) r0 = 0
    28: (95) exit

  $ sudo bpftool prog dump jited name hello
    int hello(void * ctx):
    bpf_prog_b1f8218e038bd6c4_hello:
    ; int hello(void *ctx) {
    0: nopl (%rax,%rax)
    5: nop
    7: pushq %rbp
    8: movq %rsp, %rbp
    b: subq $16, %rsp
    12: xorl %edi, %edi
    ; u64 counter = 0;
    14: movq %rdi, -16(%rbp)
    ; uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    18: callq 0xffffffffcaadd1c8
    ; uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    1d: shlq $32, %rax
    21: shrq $32, %rax
    ; uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    25: movq %rax, -8(%rbp)
    ; p = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -1), &uid);
    29: movabsq $-120964170655744, %rdi
    33: movq %rbp, %rsi
    ;
    36: addq $-8, %rsi
    ; p = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -1), &uid);
    3a: callq 0xffffffffcaae4d28
    3f: testq %rax, %rax
    42: je 0x48
    44: addq $56, %rax
    48: movl $1, %edi
    ; if (p != 0) {
    4d: testq %rax, %rax
    50: je 0x5e
    ; counter = *p;
    52: movq (%rax), %rdi
    ; counter = *p;
    56: movq %rdi, -16(%rbp)
    ; }
    5a: addq $1, %rdi
    ; counter++;
    5e: movq %rdi, -16(%rbp)
    ; bpf_map_update_elem((void *)bpf_pseudo_fd(1, -1), &uid, &counter, BPF_ANY);
    62: movabsq $-120964170655744, %rdi
    6c: movq %rbp, %rsi
    ;
    6f: addq $-8, %rsi
    73: movq %rbp, %rdx
    76: addq $-16, %rdx
    ; bpf_map_update_elem((void *)bpf_pseudo_fd(1, -1), &uid, &counter, BPF_ANY);
    7a: xorl %ecx, %ecx
    7c: callq 0xffffffffcaae7b08
    ; return 0;
    81: xorl %eax, %eax
    83: leave
    84: retq
    85: int3
  ```

- [hello-buffer.py](../chapter2/hello-buffer.py)

  ```console
  $ sudo bpftool prog show
  ...
  302: kprobe  name hello  tag e48a7d087c1ccf3b  gpl
    loaded_at 2024-02-29T12:40:45+0200  uid 0
    xlated 296B  jited 164B  memlock 4096B  map_ids 101
    btf_id 400
    pids python3(94172)

  $ sudo bpftool prog dump xlated name hello
  int hello(void * ctx):
  ; int hello(void *ctx) {
   0: (bf) r6 = r1
   1: (b7) r1 = 0
  ; struct data_t data = {};
   2: (63) *(u32 *)(r10 -8) = r1
   3: (7b) *(u64 *)(r10 -16) = r1
   4: (7b) *(u64 *)(r10 -24) = r1
   5: (7b) *(u64 *)(r10 -32) = r1
   6: (b7) r1 = 6581362
  ; char message[12] = "Hello World";
   7: (63) *(u32 *)(r10 -48) = r1
   8: (18) r1 = 0x6f57206f6c6c6548
  10: (7b) *(u64 *)(r10 -56) = r1
  ; data.pid = bpf_get_current_pid_tgid() >> 32;
  11: (85) call bpf_get_current_pid_tgid#234960
  ; data.pid = bpf_get_current_pid_tgid() >> 32;
  12: (77) r0 >>= 32
  ; data.pid = bpf_get_current_pid_tgid() >> 32;
  13: (63) *(u32 *)(r10 -40) = r0
  ; data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  14: (85) call bpf_get_current_uid_gid#235520
  ; data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  15: (63) *(u32 *)(r10 -36) = r0
  ; struct data_t data = {};
  16: (bf) r1 = r10
  17: (07) r1 += -32
  ; bpf_get_current_comm(&data.command, sizeof(data.command));
  18: (b7) r2 = 16
  19: (85) call bpf_get_current_comm#235664
  ; struct data_t data = {};
  20: (bf) r1 = r10
  21: (07) r1 += -16
  22: (bf) r3 = r10
  ;
  23: (07) r3 += -56
  ; bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
  24: (b7) r2 = 12
  25: (85) call bpf_probe_read_kernel#-119856
  ; bpf_perf_event_output(ctx, bpf_pseudo_fd(1, -1), CUR_CPU_IDENTIFIER, &data, sizeof(data));
  26: (18) r2 = map[id:101]
  28: (bf) r4 = r10
  ;
  29: (07) r4 += -40
  ; bpf_perf_event_output(ctx, bpf_pseudo_fd(1, -1), CUR_CPU_IDENTIFIER, &data, sizeof(data));
  30: (bf) r1 = r6
  31: (18) r3 = 0xffffffff
  33: (b7) r5 = 36
  34: (85) call bpf_perf_event_output#-109472
  ; return 0;
  35: (b7) r0 = 0
  36: (95) exit

  $ sudo bpftool prog dump jited name hello
  int hello(void * ctx):
  bpf_prog_e48a7d087c1ccf3b_hello:
  ; int hello(void *ctx) {
   0: nopl (%rax,%rax)
   5: nop
   7: pushq %rbp
   8: movq %rsp, %rbp
   b: subq $56, %rsp
  12: pushq %rbx
  13: movq %rdi, %rbx
  16: xorl %edi, %edi
  ; struct data_t data = {};
  18: movl %edi, -8(%rbp)
  1b: movq %rdi, -16(%rbp)
  1f: movq %rdi, -24(%rbp)
  23: movq %rdi, -32(%rbp)
  27: movl $6581362, %edi
  ; char message[12] = "Hello World";
  2c: movl %edi, -48(%rbp)
  2f: movabsq $8022916924116329800, %rdi
  39: movq %rdi, -56(%rbp)
  ; data.pid = bpf_get_current_pid_tgid() >> 32;
  3d: callq 0xffffffffcaadcfa0
  ; data.pid = bpf_get_current_pid_tgid() >> 32;
  42: shrq $32, %rax
  ; data.pid = bpf_get_current_pid_tgid() >> 32;
  46: movl %eax, -40(%rbp)
  ; data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  49: callq 0xffffffffcaadd1d0
  ; data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  4e: movl %eax, -36(%rbp)
  ; struct data_t data = {};
  51: movq %rbp, %rdi
  54: addq $-32, %rdi
  ; bpf_get_current_comm(&data.command, sizeof(data.command));
  58: movl $16, %esi
  5d: callq 0xffffffffcaadd260
  ; struct data_t data = {};
  62: movq %rbp, %rdi
  65: addq $-16, %rdi
  69: movq %rbp, %rdx
  ;
  6c: addq $-56, %rdx
  ; bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
  70: movl $12, %esi
  75: callq 0xffffffffcaa865a0
  ; bpf_perf_event_output(ctx, bpf_pseudo_fd(1, -1), CUR_CPU_IDENTIFIER, &data, sizeof(data));
  7a: movabsq $-120954666075136, %rsi
  84: movq %rbp, %rcx
  ;
  87: addq $-40, %rcx
  ; bpf_perf_event_output(ctx, bpf_pseudo_fd(1, -1), CUR_CPU_IDENTIFIER, &data, sizeof(data));
  8b: movq %rbx, %rdi
  8e: movl $4294967295, %edx
  93: movl $36, %r8d
  99: callq 0xffffffffcaa88e30
  ; return 0;
  9e: xorl %eax, %eax
  a0: popq %rbx
  a1: leave
  a2: retq
  a3: int3

  ```

- [hello-tail.py](../chapter2/hello-tail.py)

  ```console
  $ sudo bpftool prog show
    ...
    328: raw_tracepoint  name hello  tag 9b77eaf7d1a6840f  gpl
        loaded_at 2024-02-29T12:46:32+0200  uid 0
        xlated 160B  jited 166B  memlock 4096B  map_ids 114
        btf_id 432
        pids python3(95416)
    329: raw_tracepoint  name ignore_opcode  tag a04f5eef06a7f555  gpl
        loaded_at 2024-02-29T12:46:32+0200  uid 0
        xlated 16B  jited 16B  memlock 4096B
        btf_id 432
        pids python3(95416)
    330: raw_tracepoint  name hello_exec  tag d0e36209a2ef1b3e  gpl
        loaded_at 2024-02-29T12:46:32+0200  uid 0
        xlated 112B  jited 76B  memlock 4096B
        btf_id 432
        pids python3(95416)
    331: raw_tracepoint  name hello_timer  tag 4db4fdc0ba974dc5  gpl
        loaded_at 2024-02-29T12:46:32+0200  uid 0
        xlated 352B  jited 207B  memlock 4096B
        btf_id 432
        pids python3(95416)

  $ sudo bpftool prog dump xlated name hello
    int hello(struct bpf_raw_tracepoint_args * ctx):
    ; int opcode = ctx->args[1];
    0: (79) r6 = *(u64 *)(r1 +8)
    ; bpf_tail_call_((void *)bpf_pseudo_fd(1, -1), ctx, opcode);
    1: (18) r2 = map[id:114]
    ; ((void (*)(void *, u64, int))BPF_FUNC_tail_call)(ctx, map_fd, index);
    3: (bf) r3 = r6
    4: (85) call bpf_tail_call#12
    5: (b7) r1 = 6563104
    ; ({ char _fmt[] = "Another syscall: %d"; bpf_trace_printk_(_fmt, sizeof(_fmt), opcode); });
    6: (63) *(u32 *)(r10 -16) = r1
    7: (18) r1 = 0x3a6c6c6163737973
    9: (7b) *(u64 *)(r10 -24) = r1
    10: (18) r1 = 0x20726568746f6e41
    12: (7b) *(u64 *)(r10 -32) = r1
    13: (bf) r1 = r10
    ;
    14: (07) r1 += -32
    ; ({ char _fmt[] = "Another syscall: %d"; bpf_trace_printk_(_fmt, sizeof(_fmt), opcode); });
    15: (b7) r2 = 20
    16: (bf) r3 = r6
    17: (85) call bpf_trace_printk#-108416
    ; return 0;
    18: (b7) r0 = 0
    19: (95) exit

  $ sudo bpftool prog dump jited name hello
    int hello(struct bpf_raw_tracepoint_args * ctx):
    bpf_prog_9b77eaf7d1a6840f_hello:
    ; int opcode = ctx->args[1];
    0: nopl (%rax,%rax)
    5: xorl %eax, %eax
    7: pushq %rbp
    8: movq %rsp, %rbp
    b: subq $32, %rsp
    12: pushq %rax
    13: pushq %rbx
    14: movq 8(%rdi), %rbx
    ; bpf_tail_call_((void *)bpf_pseudo_fd(1, -1), ctx, opcode);
    18: movabsq $-120950437310464, %rsi
    ; ((void (*)(void *, u64, int))BPF_FUNC_tail_call)(ctx, map_fd, index);
    22: movq %rbx, %rdx
    25: movl %edx, %edx
    27: cmpl %edx, 36(%rsi)
    2a: jbe 0x61
    2c: movl -36(%rbp), %eax
    32: cmpl $33, %eax
    35: jae 0x61
    37: addl $1, %eax
    3a: movl %eax, -36(%rbp)
    40: movq 272(%rsi,%rdx,8), %rcx
    48: testq %rcx, %rcx
    4b: je 0x61
    4d: popq %rbx
    4e: popq %rax
    4f: addq $32, %rsp
    56: movq 48(%rcx), %rcx
    5a: addq $11, %rcx
    5e: jmpq *%rcx
    60: int3
    61: movl $6563104, %edi
    ; ({ char _fmt[] = "Another syscall: %d"; bpf_trace_printk_(_fmt, sizeof(_fmt), opcode); });
    66: movl %edi, -16(%rbp)
    69: movabsq $4209858917220710771, %rdi
    73: movq %rdi, -24(%rbp)
    77: movabsq $2338042655863172673, %rdi
    81: movq %rdi, -32(%rbp)
    85: movq %rbp, %rdi
    ;
    88: addq $-32, %rdi
    ; ({ char _fmt[] = "Another syscall: %d"; bpf_trace_printk_(_fmt, sizeof(_fmt), opcode); });
    8c: movl $20, %esi
    91: movq %rbx, %rdx
    94: movq -40(%rbp), %rax
    9b: callq 0xffffffffcaa8924c
    ; return 0;
    a0: xorl %eax, %eax
    a2: popq %rbx
    a3: leave
    a4: retq
    a5: int3
  ```

### Exercise 3

Run [hello-tail.py](../chapter2/hello-tail.py) from the [chapter2 directory](../chapter2/), and while it’s running, take a look at the programs it loaded.
You’ll see that each tail call program is listed individually, like this:

```console
$ bpftool prog list
...
120: raw_tracepoint name hello tag b6bfd0e76e7f9aac gpl
loaded_at 2023-01-05T14:35:32+0000 uid 0
xlated 160B jited 272B memlock 4096B map_ids 29
btf_id 124
pids hello-tail.py(3590)
121: raw_tracepoint name ignore_opcode tag a04f5eef06a7f555 gpl
loaded_at 2023-01-05T14:35:32+0000 uid 0
xlated 16B jited 72B memlock 4096B
btf_id 124
pids hello-tail.py(3590)
122: raw_tracepoint name hello_exec tag 931f578bd09da154 gpl
loaded_at 2023-01-05T14:35:32+0000 uid 0
xlated 112B jited 168B memlock 4096B
btf_id 124
pids hello-tail.py(3590)
123: raw_tracepoint name hello_timer tag 6c3378ebb7d3a617 gpl
loaded_at 2023-01-05T14:35:32+0000 uid 0
xlated 336B jited 356B memlock 4096B
btf_id 124
pids hello-tail.py(3590)
```

You could also use `bpftool prog dump xlated` to look at the bytecode instructions and compare them to what you saw in “BPF to BPF Calls” on page 54.

**Solution:** Already did this in [Exercise 2](#exercise-2).

### Exercise 4

Be careful with this one, as it may be best to simply think about why this happens rather than trying it!
If you return a 0 value from an XDP program, this corresponds to `XDP_ABORTED`, which tells the kernel to abort any further processing of this packet.
This might seem a bit counterintuitive given that the 0 value usually indicates success in C, but that’s how it is.
So, if you try modifying the program to return 0 and attach it to a virtual machine’s `eth0` interface, all network packets will get dropped.
This will be somewhat unfortunate if you’re using SSH to attach to that machine, and you’ll likely have to reboot the machine to regain access!
You could run the program within a container so that the XDP program is attached to a virtual Ethernet interface that only affects that container and not the whole virtual machine.
There’s an example of doing this at <https://github.com/lizrice/lb-from-scratch>.

**Solution:** I did this, and as expected I was not able to load any website or do any network connection from my machine until I detached the program.
