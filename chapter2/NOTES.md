# Chapter 2: eBPF's "Hello World"

[**BCC** - **BPF** **C**ompiler **C**ollection](https://github.com/iovisor/bcc) - a set of tools for developing eBPF programs.
Not suitable for production use.

**execve** - a syscall used to execute a program.
`execve` is a standard interface in Linux, but the name of the function that implements it depends on the chip architecture.
BCC gives us an easy way to lookup the function name on the machine we're executing our code.

```python
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
```

Now `syscall` is the name of the function that implements the `execve` syscall.
We want to attach the program on this function via a `kprobe`.

(On my machine the function name was `__x64_sys_execve`.)

```python
b.attach_kprobe(event=syscall, fn_name="hello")
```

## Notes

- [BPF map types defined in the Kernel code](https://elixir.bootlin.com/linux/v5.15.86/source/include/uapi/linux/bpf.h#L878)
- [Kernel docs on BPF maps](https://docs.kernel.org/bpf/maps.html)

## Links

- [ ] [Introduction to CAP_BPF](https://mdaverde.com/posts/cap-bpf/)
- [ ] [BPF ring buffer](https://nakryiko.com/posts/bpf-ringbuf/)
- [ ] [Difference between process and thread groups ids](https://www.gnu.org/software/libc/manual/html_node/Process-Identification.html)
- [ ] [The Cost of BPF Tail Calls](https://pchaigno.github.io/ebpf/2021/03/22/cost-bpf-tail-calls.html)

## Exercises

### Exercise 1

Adapt the [hello-buffer.py](./hello-buffer.py) eBPF program to output different trace messages for odd and even process IDs.

**Solution:** [Here](./hello-buffer-ex-1.py)

### Exercise 2

Modify [hello-map.py](./hello-map.py) so that the eBPF code gets triggered by more than one syscall.
For example, `openat()` is commonly called to open files, and `write()` is called to write data to a file.
You can start by attaching the hello eBPF program to multiple syscall kprobes.
Then try having modified versions of the hello eBPF program for different syscalls, demonstrating that you can access the same map from multiple different programs.

**Solution:** [Here](./hello-map-ex-2.py)

### Exercise 3

The [hello-tail.py](./hello-tail.py) eBPF program is an example of a program that attaches to the `sys_enter` raw tracepoint that is hit whenever any syscall is called.
Change [hello-map.py](./hello-map.py) to show the total number of syscalls made by each user ID, by attaching it to that same `sys_enter` raw tracepoint.
Here’s some example output I got after making that change:

```console
$ ./hello-map.py
ID 104: 6 ID 0: 224
ID 104: 6 ID 101: 34 ID 100: 45 ID 0: 332 ID 501: 19
ID 104: 6 ID 101: 34 ID 100: 45 ID 0: 368 ID 501: 38
ID 104: 6 ID 101: 34 ID 100: 45 ID 0: 533 ID 501: 57
```

### Exercise 4

The `RAW_TRACEPOINT_PROBE` macro provided by BCC simplifies attaching to raw tracepoints, telling the user space BCC code to automatically attach it to a specified tracepoint.
Try it in [hello-tail.py](./hello-tail.py), like this:

- Replace the definition of the `hello()` function with `RAW_TRACEPOINT_PROBE(sys_enter)`.
- Remove the explicit attachment call `b.attach_raw_tracepoint()` from the Python code.

You should see that BCC automatically creates the attachment and the program works exactly the same.
This is an example of the many convenient macros that BCC provides.

### Exercise 5

You could further adapt [hello_map.py](./hello-map.py) so that the key in the hash table identifies a particular syscall (rather than a particular user).
The output will show how many times that syscall has been called across the whole system.
