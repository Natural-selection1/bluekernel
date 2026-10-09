# Build the BlueKernel via GN

We are using GN to build the BlueKernel. This repo contains toolchain and flag configuration to
build the BlueKernel across multiple platforms.

## Dynamic loading

Dynamic loading has one capability switch and a separate boot installation
policy. These are GN arguments, rather than Cargo features:

| Argument / cfg | Purpose |
| --- | --- |
| `dynamic_loader` | Enables the kernel application runtime, shared `libc.so.1`, dynamic shell and dynamic example build targets. Also passed to the kernel as `cfg(dynamic_loader)`. |
| `boot_dynamic_seed` | Builds the QEMU boot image and catalog that install host artifacts into tmpfs over semihosting. Requires `dynamic_loader`; it does not select the shell's linkage. |
| `dynamic_image` | Rust cfg added automatically by `dynamic_app` and `blueos_dso`. Selects dynamic startup and runtime glue in code shared with static targets. This is not a user option. |

Board files provide defaults through `board_dynamic_loader` and
`board_boot_dynamic_seed`. The five QEMU loader boards enable both by default;
other boards default to both disabled. `CONFIG_ENABLE_VFS=y` is required for
the kernel application runtime.

To build dynamic applications without the semihosting boot installation:

```sh
gn gen out/loader --args='board="qemu_mps2_an385" build_type="release" dynamic_loader=true boot_dynamic_seed=false'
ninja -C out/loader shell
```

This produces a dynamic shell that can be installed through another storage
path. The dynamic shell's `shell_runner` and the boot seed runtime tests require
the installation policy. The board's `shell_default` target builds just the shell
when that policy is disabled. To select the static shell and disable the kernel
application runtime, set `dynamic_loader=false`; `boot_dynamic_seed` then defaults
to false.

`dynamic_atomic` is an RV32 dependency label for software atomic operations,
rather than a loader feature. Application ABI headers, syscall registration,
libc application contexts and VFS helpers are architecture-independent and do
not need architecture cfgs. A kernel with `dynamic_loader=false` retains the
syscall numbers and returns `ENOSYS` for application lifecycle calls.

ARM loader profiles select soft/hard-float calling conventions using the
built-in `target_abi` cfg (`eabi`/`eabihf`). Custom CPU cfgs such as `armv7m` and
`armv8m` remain for instructions and hardware behavior that differ between
CPU generations, including cache maintenance; they are not loader switches.
