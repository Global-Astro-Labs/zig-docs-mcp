# Zig Changes: 0.13.0 to 0.15.2

## The New I/O Paradigm: `std.Io`

`std.Io` replaces the old generic Reader/Writer pattern with a concrete, buffer-in-the-interface design.

### Key Changes

**Old pattern (generic, buffer in implementation):**
```zig
fn process(reader: anytype, writer: anytype) !void {
    var buf_reader = std.io.bufferedReader(reader);
    // ...
}
```

**New pattern (concrete, buffer above vtable):**
```zig
fn process(reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    try writer.writeAll("hello");
}
```

### The `Io` Parameter

Functions that do I/O now take an `io: Io` parameter:

```zig
const std = @import("std");
const Io = std.Io;

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa);
    defer threaded.deinit();

    const io = threaded.io();
    try doRequest(io, gpa);
}

fn doRequest(io: Io, gpa: std.mem.Allocator) !void {
    var http_client: std.http.Client = .{ .allocator = gpa, .io = io };
    // ...
}
```

Without an `io` parameter, create a single-threaded instance:

```zig
var threaded: Io.Threaded = .init_single_threaded;
const io = threaded.io();
```

### Async/Concurrency Primitives

`std.Io` provides structured concurrency:

```zig
// async/await
const future = io.async(downloadFile, .{ url, output_path });
const result = try future.await(io);

// concurrent - *must* be done concurrently for correctness (requires allocation)
const concurrent_task = io.concurrent(heavyComputation, .{ data });
concurrent_task.cancel(io);

// select - block on multiple futures
switch (io.select(&.{ dns_future, timeout_future })) {
    .dns => |result| handleDns(result),
    .timeout => |err| handleTimeout(err),
}

// Group - manage many async tasks
var group: Io.Group = .init;
group.async(io, task1, .{});
group.async(io, task2, .{});
try group.wait(io);
```

### Queue: Many-Producer, Many-Consumer

```zig
var queue: Io.Queue(Result) = .init(&buffer);
queue.putOne(io, result);       // suspends if buffer full
const item = try queue.getOne(io);  // suspends if buffer empty
```

### Networking with `std.Io.net`

`std.net` is deleted. Use `std.Io.net`:

```zig
const host_name: std.Io.net.HostName = try .init("example.com");
const stream = try host_name.connect(io, 80, .{});
```

### Writer Interface Changes

Format methods are simplified:

```zig
// Old:
pub fn format(
    this: @This(),
    comptime format_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void

// New:
pub fn format(this: @This(), writer: *std.io.Writer) std.io.Writer.Error!void
```

Format string changes:
- `"{}"` no longer calls `format` methods
- `"{f}"` explicitly calls a `format` method
- `"{any}"` skips format methods entirely

### Writing to ArrayList: `Writer.Allocating`

```zig
var list: std.ArrayList(u8) = .empty;
defer list.deinit(gpa);

var writer = std.Io.Writer.Allocating{
    .underlying_writer = &list.writer_no_allocator,
    .allocator = gpa,
};
try writer.print("count: {d}", .{42});
```

Or simply use `list.print()` which handles allocation internally.

---

## Language Features

### Labeled Switch

Switch statements can be labeled and targeted by `continue` for finite state machines:

```zig
const State = enum { start, middle, end };

var state = State.start;
var count: u32 = 0;

state_machine: switch (state) {
    .start => {
        state = .middle;
        continue :state_machine state;
    },
    .middle => {
        count += 1;
        if (count < 5) continue :state_machine state;
        state = .end;
        continue :state_machine state;
    },
    .end => {},
}
```

### Decl Literals

Enum literal syntax (`.foo`) now extends to any declaration. Given result type `S`, `.default` is equivalent to `S.default`:

```zig
const Config = struct {
    pub const default: Config = .{
        .timeout = 30,
        .retries = 3,
    };

    timeout: u32,
    retries: u32,
};

const cfg: Config = .default;
```

Works for any namespace member. Consequence: fields and declarations can no longer share names within the same struct.

### @splat for Arrays

```zig
const arr: [4]i32 = @splat(42);        // [42, 42, 42, 42]
const sentinel: [4:0]i32 = @splat(0);  // sentinel-terminated too
```

### std.enums.tagName Preserves Sentinel

```zig
const name = std.enums.tagName(Color, .red);  // Returns [:0]const u8, not []const u8
```

Safe alternative to `@tagName()` for non-exhaustive enums — doesn't panic on untagged values.

### @branchHint Replaces @setCold

`@branchHint(.cold)` as first statement in a block. Available hints: `.likely`, `.unlikely`, `.cold`, `.unpredictable`.

### @ptrCast with Slices

`@ptrCast` now allows changing slice length:

```zig
const bytes: []const u8 = &.{ 0, 0, 0, 0, 1, 0, 0, 0 };
const ints: []const u32 = @ptrCast(bytes);  // 2 u32s
```

### Calling Convention Overhaul

`CallingConvention` is now a tagged union. Convention names are lowercase (`.c` not `.C`). `@setAlignStack` is removed — use calling convention options instead.

---

## Standard Library Changes

### Allocator Reorganization

**GeneralPurposeAllocator is now DebugAllocator:**

```zig
// Old:
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

// New:
var gpa = std.heap.DebugAllocator(.{}){};
```

**SmpAllocator** is the new production allocator: `std.heap.smp_allocator`.

### ArrayList is Now Unmanaged-Style

Allocator is passed to methods, not stored:

```zig
// Old:
var list = std.ArrayList(i32).init(gpa);
defer list.deinit();
list.append(42);

// New:
var list: std.ArrayList(i32) = .empty;
defer list.deinit(gpa);
list.append(gpa, 42);
```

`std.ArrayListUnmanaged` is now just an alias to `std.ArrayList`. Same for `ArrayHashMap` and `HashMap`.

### Runtime Page Size

`std.mem.page_size` is removed. Use `std.heap.pageSize()`.

### ZON: Zig Object Notation

Parse at runtime:

```zig
const config = try std.zon.parse.fromSlice(std.heap.page_allocator, Config, config_zon);
```

Or import at compile time:

```zig
const config: Config = @import("config.zon");
```

ZON is a subset of Zig syntax — supports structs, arrays, enums, unions, primitives.

### New Panic Interface

```zig
pub const std_options: std.Options = .{
    .panicFn = myPanicHandler,
};

fn myPanicHandler(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    std.process.abort();
}
```

### TLS Support

`std.crypto.tls` provides TLS 1.3 client support:

```zig
const tls_client = std.crypto.tls.Client.init(conn, .{
    .host = .{ .explicit = "example.com" },
    .ca_bundle = ca_bundle,
});
```

### Allocator API Additions

- `Allocator.remap()` for growing/shrinking in-place
- `Alignment` type replaces raw `u8` for alignment values

---

## Build System Changes

### Module-Based Artifacts

```zig
// Old:
const exe = b.addExecutable(.{
    .name = "myapp",
    .root_source_file = b.path("src/main.zig"),
    .target = target,
    .optimize = optimize,
});

// New:
const mod = b.createModule(.{
    .root_source_file = b.path("src/main.zig"),
    .target = target,
    .optimize = optimize,
});
const exe = b.addExecutable(.{
    .name = "myapp",
    .root_module = mod,
});
```

### Package Hash Format

Package hashes are now human-readable: `{name}-{version}-{fingerprint}-{hash}`.

### addLibrary Replaces addSharedLibrary/addStaticLibrary

```zig
const lib = b.addLibrary(.{
    .name = "mylib",
    .root_module = mod,
    .linkage = .dynamic,  // or .static
});
```

### File System Watching

`zig build --watch` with `--debounce <ms>`. Build runner persists across rebuilds.

---

## std.builtin.Type Renamed

All fields are now lowercase:

| Old | New |
|-----|-----|
| `.Int` | `.int` |
| `.Struct` | `.@"struct"` |
| `.Pointer.Size.One` | `.one` |
| `.Pointer.Size.Many` | `.many` |
| `.Pointer.Size.Slice` | `.slice` |
| `.Pointer.Size.C` | `.c` |

---

## New Builtins

| Builtin | Purpose |
|---------|---------|
| `@branchHint(hint)` | Branch prediction hints |
| `@FieldType(T, "field")` | Replace `std.meta.FieldType` |
| `@disableInstrumentation()` | Exclude code from fuzzer coverage |
| `@memmove` | Like C memmove (handles overlap) |

## Removed Builtins

| Old | Replacement |
|-----|-------------|
| `@fence(order)` | Stronger atomic orderings |
| `@setCold(bool)` | `@branchHint(.cold)` |
| `@setAlignStack(n)` | Calling convention options |
| `@Type(info)` | `@Int`, `@Enum`, `@Struct`, etc. |
