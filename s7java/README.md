# s7java — minimal S7 node in Java (in progress)

A second independent implementation of the S7 data stream protocol
(`../doc/S7_Network_Wire_Protocol_v1.md`), to check that the protocol is implementable from its
specification in another language. Standard library only, Java 21 or later.

Implemented so far:

- `s7.wire`: the wire format v1 (every type of section 8, 12-bit packing, `TIMESTAMPS` and
  `SEND_TIME` extensions, `ACK` / `RESUME` / `RESUME_NO_STATE`), with the checks of
  `s7transport`'s `wire_format.cpp` in the same order;
- `s7.stream.StreamDescriptor`: stream descriptors as `s7net` reads them;
- `s7.json`: a small JSON reader and writer (integers and reals kept apart, as Boost.JSON does).

## Build and test

```bash
./build.sh --test   # "76 of 76 fixtures pass"
```

Set `JAVAC` / `JAVA` when the tools on `PATH` are older than Java 21, for example
`JAVAC=/usr/lib/jvm/java-25-openjdk-amd64/bin/javac ./build.sh --test`.
