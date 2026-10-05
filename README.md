# low-latency-exchange

This is my from-scratch implementation of a NASDAQ-style electronic exchange in C++23: order entry, matching, market data, persistence and failover. It is built the way a real venue would have to be, with every layer covered by tests and the trickiest parts checked by model checkers and a deterministic simulator. Nothing in the exchange path comes from an outside library.

## How it fits together

Orders arrive over SoupBinTCP sessions as OUCH 5.0 messages. A single sequencer stamps every input and writes it to an event-sourced journal before anything acts on it. A single-threaded, deterministic matching engine applies the journal, so every output is a pure function of the input log. That one property is what makes replay, snapshots, the hot standby and whole-system simulation possible. Market data goes out as ITCH 5.0 over MoldUDP64 on two independently packetized lines, and clients arbitrate between the A and B feeds and recover gaps from a re-request server or a snapshot.

### Matching engine

Continuous trading with price-time priority, plus the opening, closing and halt auctions with imbalance messages, limit up-limit down bands, halts and IPO releases. Every order passes pre-trade risk checks before it can rest or trade: price collars, size and notional limits, rate limits, credit exposure, and a kill switch. The protocols are implemented to the letter of the published specs, with golden byte tests for every message type.

### Order book

The book started as the textbook version, a map of price levels with a linked list per level, and I am optimizing it one measured experiment at a time. Each experiment records its hypothesis, the diff, and before and after measurements on real ITCH data. The goal is to take the median from about 310 ns per message down to 42 ns, and to process 18 million messages per second on a single core, over at least 14 experiments. Every variant is differentially fuzzed against a deliberately simple reference book, with a target of more than 2 billion random operations.

### Networking and kernel bypass

The same protocol stack runs over four backends: plain epoll, kernel busy polling, io_uring, and AF_XDP with an XDP steering program and my own user-space TCP. Tick-to-trade is measured with NIC hardware timestamps on both ends of the wire. What I'm aiming for: 14 us at the median and 38 us at p99 on the AF_XDP path, a p99 3.1 times lower than epoll, and 4.2 million messages per second end to end on 8 cores.

### Deterministic simulation

Time, the network and the disk all sit behind interfaces, so the production code can run inside a seeded simulator. The simulator injects packet loss, reordering, partitions, process and host crashes, torn writes and disk stalls, and checks the results against oracles such as exactly-once fills and byte-identical regeneration. Any failure replays exactly from its seed. The target is 23 genuine bugs found this way, each with a regression test.

### Hot-standby failover

A backup node follows the primary by state machine replication, and a small durable witness decides who may take over. The goal is a takeover in under 50 ms with no lost or duplicated fills. I wrote the protocol in TLA+ and model-checked it for safety and liveness, and the implementation's traces are validated against the spec. The lock-free SPSC and MPSC queues between pipeline stages are model-checked with GenMC under the RC11 and IMM memory models.

### Logging

The logger follows the NanoLog approach: the hot path writes a compact binary record, and formatting happens offline in a separate tool. Format strings are checked at compile time. The target is 9 ns per hot-path call, so logging can stay on in production.

## Measuring

All performance figures above are goals. I measure them on dedicated, isolated hardware, under a methodology I fixed before running anything, and only report what was actually measured.

## Building

Requirements: CMake 3.28 or newer, Ninja, and a C++23 compiler (Apple clang 16+, clang 21 or GCC 15). On Linux the network backends also need liburing and libbpf.

```bash
cmake --preset dev            # Debug; other presets: release, bench, asan-ubsan, tsan, msan, fuzz, sim
cmake --build build/dev
ctest --test-dir build/dev --output-on-failure
```

Running the simulator:

```bash
cmake --preset sim && cmake --build build/sim
build/sim/sim/exsim --seed=1 --seeds=1000 --check-determinism --quiet
```

## Where things live

- `src/`: the libraries (protocols, order books, engine, sequencer, journal, networking, replication, logger)
- `apps/`: `exchanged` (the exchange node), `witnessd`, the reference client, the load generator, the tick-to-trade harness, and replay and inspection tools
- `sim/`: the deterministic simulator
- `verify/`: TLA+ specs and GenMC harnesses
- `tests/`, `fuzz/`, `bench/`: tests, fuzz targets and benchmarks
- `tools/`, `lab/`, `results/`: evidence tooling, benchmark campaign definitions and recorded verification runs

The real-day tests use NASDAQ's public TotalView-ITCH sample files. `tools/itch_fetch.sh` downloads them into `data/`, which isn't committed; CI uses synthetic days instead.
