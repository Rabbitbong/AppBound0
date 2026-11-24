# AppBound0

AppBound0 is a Chrome and Edge App-Bound Encryption bypass that recovers the app-bound key from the browser's elevation service and decrypts cookies and saved passwords. `build.bat` produces two artifacts: `AppBound0.exe`, a standalone .NET command-line tool, and `abe.x64.o`, a Beacon Object File (BOF) that returns the key.

Tested with Chrome 157.0.8103.39 and Edge 158.0.4370.33.

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
- elevation_service_idl.idl
- caller_validation.cc
- google_chrome_install_modes.h
<!-- TODO author: add chromium.googlesource.com links for the three files above -->

## License

MIT. See LICENSE.
