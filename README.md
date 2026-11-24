# AppBound0

AppBound0 is a Chrome and Edge App-Bound Encryption bypass that recovers the app-bound key from the browser's elevation service and decrypts cookies and saved passwords. `build.bat` produces two artifacts: `AppBound0.exe`, a standalone .NET command-line tool, and `abe.x64.o`, a Beacon Object File (BOF) that returns the key.

Tested with Chrome 157.0.8103.39 and Edge 158.0.4370.33.

## How it works

The elevation service that owns the ABE master key refuses callers whose
image is not a recognised Chrome or Edge binary. On the Chromium side
`caller_validation.cc` rejects any process whose main executable is not
the real browser binary in the real install directory. The route around
that check is to make the call from inside a real browser process.

### Primary route: COM chain

`AppBound0.exe` and the BOF `abe.x64.o` both follow the same flow: read
`Local State`, pull `app_bound_encrypted_key`, base64-decode it, strip
the `APPB` prefix, and hand the resulting blob to `DecryptData` on an
`IElevator` or `IElevator2` interface (slot 5 on the standard Chromium
layout, slot 8 on Edge 158's placeholder-prefixed `IElevator3Edge`). The
call runs inside a trusted browser process, so `caller_validation.cc`
accepts it and the elevation service returns the 32-byte AES-256-GCM key.

Getting that code inside the browser has two modes.

For Chrome, the tool spawns `chrome.exe` headless against a throwaway
profile, allocates memory in the child, writes a position-independent
stub (built from `stub.c`, zero imports, no CRT), writes the parameter
struct and candidate chain next to it, maps a shared section back into
both processes, and starts a remote thread on the stub. The stub drives
`CoInitializeEx`, `CoCreateInstance`, `CoSetProxyBlanket` and
`DecryptData` from inside the genuine `chrome.exe` and writes the
plaintext key into the shared section.

For Edge, a fresh headless `msedge.exe` access-violates inside `combase`
the moment a remote thread touches COM, so the spawn-and-inject path
does not work. The tool attaches to the user's already-running
`msedge.exe` main browser instead, where COM is fully initialised, and
injects the same stub there. If no live Edge is running, the Edge path
fails rather than spawning one.

The stub walks a candidate chain of `(CLSID, IID, slot)` tuples until
one `DecryptData` succeeds. This absorbs interface-shape drift between
the standard Chromium layout and Edge's final flavor, and between
Chrome and Edge apartment requirements.

`AppBound0.exe` prints the key as base64 for the `key` verb, or
decrypts the v20 cookie and password records with that key for the
`cookies`, `passwords` and `all` verbs. `abe.x64.o` returns the base64
key to a Sliver or Cobalt Strike beacon; cookie and password decryption
are the operator's problem on that path.

### Alternate route: HWBP

`AbeHwbp.cs` recovers the key with a hardware breakpoint (HWBP) in place
of the COM call. It spawns the browser `CREATE_SUSPENDED | DEBUG_PROCESS`
against a seeded temp profile, so the debugger is attached from birth and
every child (including the `StorageService` utility where cookie
decryption runs) routes its debug events back. On each process's
`msedge.dll` or `chrome.dll` load event the tool writes `Dr0` on every
thread to a per-build RVA that sits on the instruction loading the
plaintext key pointer into `RDX`, right before a `std::string`
constructor copies it. On the single-step trap, the handler reads 32
bytes from the debuggee at `RDX` and returns them. The shipped RVAs
target Chrome 157.0.8103.39 and Edge 157.0.4341.42; any new browser
build needs a fresh capture of the trap site. This route is a
reimplementation of the VoidStealer-class primitive; credit to that
prior art.

## Build

Run `build.bat` from the repo root. It needs MSVC 14.44, Windows SDK 10.0.26100 and the .NET Framework 4 C# compiler (csc).

Step 1 compiles `src/stub.c` to an object file with cl. Step 2 runs `src/extract_stub.py` on that object file to write the stub as byte arrays in `src/stub_blob.h` and `src/AppBound0Stub.cs`, and fails if the stub has any relocations. Step 3 compiles `src/abe.c` to the BOF `abe.x64.o`. Step 4 compiles `src/AppBound0.cs`, `src/AbeHwbp.cs` and `src/AppBound0Stub.cs` with csc into `AppBound0.exe`.

## Layout

```
build.bat
src/abe.c
src/abe_common.h
src/stub.c
src/extract_stub.py
src/stub_blob.h
src/AppBound0.cs
src/AppBound0Stub.cs
src/AbeHwbp.cs
README.md
LICENSE
```

## Chromium reference files

AppBound0's logic mirrors parts of three Chromium files, not vendored here:

- [`elevation_service_idl.idl`](https://chromium.googlesource.com/chromium/src/+/157.0.8103.39/chrome/elevation_service/elevation_service_idl.idl)
- [`caller_validation.cc`](https://chromium.googlesource.com/chromium/src/+/157.0.8103.39/chrome/elevation_service/caller_validation.cc)
- [`google_chrome_install_modes.h`](https://chromium.googlesource.com/chromium/src/+/157.0.8103.39/chrome/install_static/google_chrome_install_modes.h)

Links are pinned to the exact M157 release the code targets.

## License

MIT. See LICENSE.
