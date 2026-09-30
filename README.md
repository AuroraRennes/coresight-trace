# coresight-trace

coresight-trace is a hardware-assisted process tracer for binary-only fuzzing on ARM64 Linux.

CoreSight, implemented as hardware on some Arm-based SoCs for debugging purposes, enables tracing CPU execution with low-overhead. This project employs the feature to generate code coverage for fuzzing without compile-time instrumentation.

NOTE: coresight-trace is in the early development stage. Not applicable for production use.

## Prerequisites

### Hardware

Unlike Intel PT, not every Arm-based SoC has CoreSight as its design varies. The "Limitations" section describes the detailed hardware requirements and limitations.
coresight-trace supports the following boards (SoCs):

* NVIDIA Jetson TX2 (NVIDIA Parker)
* NVIDIA Jetson Nano (NVIDIA Tegra X1)
* GIGABYTE R181-T90 (Marvell ThunderX2 CN99XX)
* TaiShan 2280 (Hi1616)

To port coresight-trace to other boards, consult the SoC the documents whether CoreSight is available on the target.

### Environment

We tested coresight-trace on ARM64 Ubuntu 20.04 and 18.04.

coresight-trace requires bare-metal ARM64 Linux to work because it needs to access physical memories to operate CoreSight components directly. It is built on the top of customized [CSAL](https://github.com/ARM-software/CSAL), which means it does not work on VMs or containers.

coresight-trace also requires the `u-dma-buf` kernel module to use the ETR trace sink. It allocates a DMA-capable continuous physical memory region, and the tracer uses the region to store trace data.

## Getting started

To use coresight-trace for fuzzing, clone the [AFL++ CoreSight mode](https://github.com/RICSecLab/AFLplusplus-cs/tree/retrage/cs-mode-support) and check out this repository as a submodule to preserve the directory structure.

### Software Dependencies

* [RICSec/CSAL](https://github.com/RICSecLab/CSAL)
* [RICSec/coresight-decoder](https://github.com/RICSecLab/coresight-decoder)
* [ikwzm/u-dma-buf](https://github.com/ikwzm/udmabuf)

Note that coresight-decoder requires capstone disassembly library with version 4.0 or later. **Do not use the older version (e.g. `libcapstone-dev` from Ubuntu apt packages).**

### Build

coresight-trace has two build targets: `cs-trace` and `cs-proxy`.
`cs-trace` is a standalone process tracing application, which runs the traced target using fork+exec and outputs raw trace data. `cs-proxy` is a proxy application for AFL++ CoreSight mode, behaving like an AFL fork server. To use `cs-proxy` for fuzzing, read the [AFL++ CoreSight mode README](https://github.com/RICSecLab/AFLplusplus-cs/blob/retrage/cs-mode-support/cs_mode/README.md) in addition to this document.

Checkout and build:

```bash
git clone https://github.com/RICSecLab/coresight-trace.git
cd coresight-trace
git submodule update --init
DEFAULT_BOARD="Your Target Board" make
```

It will biuld `cs-proxy` only if the repository is located under the AFL++ CoreSight mode directory (In case of symbolic link `include/afl` destination `../../../include` exists).

### Install u-dma-buf

Before run cs-trace or cs-proxy, build and install the `u-dma-buf` kernel module. The allocated DMA region size is 8MB (0x800000) for instance:

```bash
cd u-dma-buf
make
sudo insmod u-dma-buf.ko udmabuf0=0x800000
```

It creates a `/dev/udmabuf0` pseudo-device.

### Run cs-trace

Run `cs-trace` as root with specifying a traced target after `--`.

```bash
sudo ./cs-trace -- path/to/bin
```

After the target exited, it generates the raw CoreSight trace binary `cstrace.bin`, and the coresight-decoder arguments list text file `decoderargs.txt` under the current directory.

To generate the coverage bitmap `edge_coverage_bitmap.out` using coresight-decoder from the trace binary, run:

```bash
./coresight-decoder/processor `cat decoderargs.txt`
```

Here is a pseudo Makefile target that does the above commands:

```bash
make decode
```

This runs `$(TRACEE)` (`tests/fib` by default) as a trace target under `trace/$(shell date +%Y-%m-%d-%H-%M-%S)` directory, then runs decoder.

`cs-trace` accepts some options. `-h` or `--help` for available options list.

### Coverage Types

coresight-trace uses [RICSec/coresight-decoder](https://github.com/RICSecLab/coresight-decoder), a new CoreSight trace decoder optimized for fuzzing feedback. It currently supports AFL-style edge coverage and [PTrix](https://github.com/junxzm1990/afl-pt)-style path coverage. Refer to the [coresight-decoder README](https://github.com/RICSecLab/coresight-decoder/blob/master/README.md) for further infomation.


### Deferred forkserver

See the example from the [tests/def_forksrv](tests/def_forksrv)

### Coverage

cs-trace, running with the `-d edge` and `-l` options, can save the instruction execution stream to a file in the current directory.

For example, after running the command:

```
CS_TRACE_LIB=libc-2.27.so ./cs-trace --decoding=edge -l  -- tests/fib
```

`coverage.txt` will be created in the current directory.

```
fib+8e4
fib+8e8
fib+8ec
fib+8f0
fib+8f4
libc-2.27.so+20748
libc-2.27.so+2074c
libc-2.27.so+20750
libc-2.27.so+20754
libc-2.27.so+20758
```

This file stores the instruction execution stream in `Module + Offset (modoff)` format, which is suitable for the [lighthouse plugin](https://github.com/gaasedelen/lighthouse/tree/master).

### Stalker decoder backend

An alternative decode backend, ported from [Stalker](https://github.com/AuroraRennes/Stalker) (Yue et al., RAID'24), is available as an opt-in build:

```bash
DEFAULT_BOARD="Your Target Board" STALKER_DECODER=1 make
```

This links the vendored decoder in [stalker-decoder](stalker-decoder) (a fork of `ptm2human`) instead of using coresight-decoder for feedback. It is opt-in because that decoder is GPLv2, the default build links none of it. Add `DECODER_VERBOSE=1` to re-enable the decoder's own packet logging.

#### Environment variables

| Variable | Applies to | Meaning |
|---|---|---|
| `AFLCS_COV` | always | Coverage type: `edge` (branch broadcast, one bitmap byte per taken branch), `path` (atom-chained path hash), or `hybrid` (Stalker backend only: each input runs in path mode, and inputs with a new path are re-run in edge mode, whose map is the one AFL++ sees). |
| `AFLCS_NO_DECODER` | always | Skip decoding entirely; report a constant bitmap. For measuring tracing overhead alone. |
| `AFLCS_REG_VERBOSE` | always | Log CoreSight register accesses during setup. |
| `AFLCS_ETM_SYNCPR` | always | Set `TRCSYNCPR.PERIOD` (A-Sync every 2^N bytes). Defaults to 0, no periodic A-Sync. |
| `AFLCS_ETM_STALLCRLR` | always | Set `TRCSTALLCTLR` (hex or decimal). Defaults to `0x2100` (upstream) on the armored backend and `0` (no stall) on Stalker. `0x10c` is ISTALL at level 3, the tuned setting. |
| `AFLCS_ETM_VICTLR` | always | Set `TRCVICTLR` (hex or decimal). Defaults to `0x201` (upstream: no exception level excluded) on the armored backend and `0x6f0201` (non-secure EL0 only) on Stalker. `0x6f0201` is the tuned armored setting. |
| `AFLCS_DRAIN_AT_2XETF` | armored backend | `1` pauses the target to drain the trace at twice the ETF size when the ETF is smaller than the ETR (tuned). Defaults to `0`, upstream's drain at the ETR size. |
| `AFLCS_STALKER_EXC_SNAPSHOT` | Stalker backend | `1` snapshots the decoder state on an exception and restores it on return (tuned). Defaults to `0`, the artifact's handling. |
| `AFLCS_TRUNCATE_ON_OVERFLOW` | armored backend | `1` stops decoding at an ETM Overflow packet (tuned). Defaults to `0`, upstream's decoding across the gap. |
| `AFLCS_RESYNC_ON_LEFTOVER` | armored backend | `1` skips leftover bytes of a cut ETM preamble at the start of a window and resyncs on the next A-Sync or in-range long address (tuned). Defaults to `0`, upstream's rejection of the trace. |
| `AFLCS_BB_VERIFY` | Stalker backend | Read back the branch-broadcast config register after writing it. |
| `AFLCS_STALKER_DIAG` | Stalker backend | Per-exec diagnostics: overflow rate, bitmap hash and nonzero-byte count. |
| `AFLCS_STALKER_DUMP_BYTES` | Stalker backend | Hex-dump the first N captured trace bytes per exec. |
| `AFLCS_STALKER_ADDRTRACE` | Stalker backend | Dump the first N reconstructed address packets (read by the decoder itself). |
| `AFLCS_FREQ_CALIBRATE` | always | Set to `0` to skip the upfront frequency-calibration ramp. On by default, matching Stalker's `cpu_frequency_analysis()`. The ramp costs one exec per available CPU frequency and is usually inert, since seeds rarely overflow. |
| `AFLCS_FREQ_GOV` | Stalker backend | Set to `0` to disable the frequency governor: the CPU policy is left untouched, with no calibration, no overflow retries and no forced-minimum run. |
| `AFLCS_EXPORT_ON_DECODE_FAIL` | coresight-decoder backend | Export each trace the decoder rejects as `cstrace-<n>.bin` + `decoderargs-<n>.txt` in the working directory, for offline replay with `coresight-decoder/processor`. |
| `AFLCS_PID_FILTER` | Stalker backend | Set to `0` to trace the address range for every process, not only the current child. On by default: the child's PID is written to the ETMs' context ID comparator at every exec, so other processes mapped at the same addresses (every PIE binary, with ASLR off) are not traced. |
| `AFLCS_FREQ_DIAG` | always | Log every CPU frequency write with its origin (calibrate/apply/force_min/restore_max) and every step up or down. |

`AFLCS_STALKER_DIAG`, `AFLCS_STALKER_DUMP_BYTES`, `AFLCS_STALKER_ADDRTRACE` and `AFLCS_FREQ_DIAG` are debugging aids and are off the hot path when unset. All of them write to the proxy's stderr, which AFL++ discards unless `AFL_DEBUG_CHILD=1` is set.

The frequency governor writes `scaling_min_freq`/`scaling_max_freq` and restores the policy it found on exit, including when the proxy is killed.

## Limitations

Currently, coresight-trace supports trace sources with ARM64 ETMv4 and later. ETMv3 or earlier is not supported. It also requires an ETR trace sink to achieve better performance.

## Contributing

Please open GitHub Issues and Pull Requests. All commits must include a `Signed-off-by` line using `git commit --signoff` to enforce the [Developer Certificate of Origin (DCO)](https://developercertificate.org).

## License

coresight-trace is released under the [Apache License, Version 2.0](https://opensource.org/licenses/Apache-2.0).

## Acknowledgements

This project has received funding from the Acquisition, Technology & Logistics Agency (ATLA) under the Innovative Science and Technology Initiative for Security 2020 (JPJ004596).
