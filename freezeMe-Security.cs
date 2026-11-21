// freezeMe-Security - keyboard + mouse locker for Windows 10/11
// (C) tomas-docx 2026
//
// Unlocks when you press your combo (keys + mouse buttons, all within ComboWindowMs).
// Build with build.bat. Has to stay C# 5 for the csc.exe that comes with Windows.
//
// Usage:
//   freezeMe-Security.exe              (double-click) settings window, install / start / test from there
//   freezeMe-Security.exe --autostart  the locker, started by the scheduled task at sign-in
//   freezeMe-Security.exe --enrol      set the unlock combo (admin)
//   freezeMe-Security.exe --test       freeze, unlock after TestSeconds
//   freezeMe-Security.exe --stop       stop it (admin)
//   (internal: --setup [--silent], --remove-task, --watchdog, --start-frozen, --no-start-freeze)
//
// Settings and the installed exe always live in C:\Program Files\freezeMe-Security.
//
// Sections (search "// 1." etc):
//   1 Names  2 Native  3 Hooks  4 Config  5 State  6 Log  7 Program
//   8 Watchdog  9 LockerForm  10 EnrolForm  11 SettingsForm
//
// Input ids: keys = virtual-key code (1-255), mouse = 1001 left, 1002 right,
// 1003 middle, 1004 back, 1005 forward. In freeze.ini: K72,K91,M3 etc.
//
// OnButton/OnMotion run inside the hook, keep them fast (Windows drops slow hooks).
// No disk or UI work in there, use BeginInvoke.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("freezeMe-Security")]
[assembly: System.Reflection.AssemblyDescription("Keyboard and mouse lock for Windows")]
[assembly: System.Reflection.AssemblyCompany("tomas-docx")]
[assembly: System.Reflection.AssemblyProduct("freezeMe-Security")]
[assembly: System.Reflection.AssemblyCopyright("(C) tomas-docx 2026")]
[assembly: System.Reflection.AssemblyVersion("1.2.1.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.2.1.0")]

namespace FreezeMeSecurity
{
    // 1. Names
    static class Names
    {
        public const string App = "freezeMe-Security";
        public const string MainMutex = @"Local\freezeMe-Security.Main";
        public const string TestMutex = @"Local\freezeMe-Security.Test";
        public const string WatchdogMutex = @"Local\freezeMe-Security.Watchdog";
        public const string StopEvent = @"Local\freezeMe-Security.Stop";
    }

    // 2. Native
    static class Native
    {
        public const int WH_KEYBOARD_LL = 13;
        public const int WH_MOUSE_LL = 14;

        public const int WM_KEYDOWN = 0x0100;
        public const int WM_KEYUP = 0x0101;
        public const int WM_SYSKEYDOWN = 0x0104;
        public const int WM_SYSKEYUP = 0x0105;

        public const int WM_MOUSEMOVE = 0x0200;
        public const int WM_LBUTTONDOWN = 0x0201;
        public const int WM_LBUTTONUP = 0x0202;
        public const int WM_RBUTTONDOWN = 0x0204;
        public const int WM_RBUTTONUP = 0x0205;
        public const int WM_MBUTTONDOWN = 0x0207;
        public const int WM_MBUTTONUP = 0x0208;
        public const int WM_XBUTTONDOWN = 0x020B;
        public const int WM_XBUTTONUP = 0x020C;

        public const int WM_WTSSESSION_CHANGE = 0x02B1;
        public const int WTS_SESSION_LOCK = 0x7;
        public const int WTS_SESSION_UNLOCK = 0x8;

        public const uint LLKHF_INJECTED = 0x10;
        public const uint LLMHF_INJECTED = 0x01;

        public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        public struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT
        {
            public int x;
            public int y;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSLLHOOKSTRUCT
        {
            public POINT pt;
            public uint mouseData;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LASTINPUTINFO
        {
            public uint cbSize;
            public uint dwTime;
        }

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll")]
        public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool LockWorkStation();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool CloseDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex, StringBuilder pvInfo, int nLength, out int lpnLengthNeeded);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSRegisterSessionNotification(IntPtr hWnd, int dwFlags);

        [DllImport("wtsapi32.dll")]
        public static extern bool WTSUnRegisterSessionNotification(IntPtr hWnd);

        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(IntPtr memory);

        // GetTickCount, same clock as GetLastInputInfo. Wraps, so keep the maths unchecked.
        public static uint Now()
        {
            return unchecked((uint)Environment.TickCount);
        }

        public static int Since(uint then)
        {
            return unchecked((int)(Now() - then));
        }

        public static uint LastInputTick()
        {
            LASTINPUTINFO l = new LASTINPUTINFO();
            l.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
            if (!GetLastInputInfo(ref l)) return Now();
            return l.dwTime;
        }

        // false on the Ctrl+Alt+Del screen, lock screen, UAC etc.
        public static bool InputDesktopIsDefault()
        {
            IntPtr h = OpenInputDesktop(0, false, 0x0001 /* DESKTOP_READOBJECTS */);
            if (h == IntPtr.Zero) return false;
            try
            {
                StringBuilder sb = new StringBuilder(256);
                int needed;
                if (!GetUserObjectInformation(h, 2 /* UOI_NAME */, sb, sb.Capacity * 2, out needed)) return false;
                return string.Equals(sb.ToString(), "Default", StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                CloseDesktop(h);
            }
        }

        // 1 = locked, 0 = unlocked, -1 = don't know. WTSINFOEXW: Level at 0, then the union
        // starts at 8 (it has LARGE_INTEGERs so it's 8-aligned): SessionId 8, SessionState 12, SessionFlags 16.
        public static int SessionLockState()
        {
            IntPtr buf;
            int bytes;
            try
            {
                if (!WTSQuerySessionInformation(IntPtr.Zero, -1, 25, out buf, out bytes)) return -1;
            }
            catch
            {
                return -1;
            }
            try
            {
                if (bytes < 20 || Marshal.ReadInt32(buf, 0) != 1) return -1;
                int flags = Marshal.ReadInt32(buf, 16);
                if (flags == 0) return 1;
                if (flags == 1) return 0;
                return -1;
            }
            finally
            {
                WTSFreeMemory(buf);
            }
        }
    }

    // 3. Hooks
    static class Hooks
    {
        // return true to swallow
        public static Func<int, bool, bool, bool, bool> OnButton;   // (id, down, up, injected)
        public static Func<bool, bool, bool> OnMotion;               // (isMove, injected) for moves and scrolls
        public static bool SwallowOnError;
        public static uint LastEventTick;

        static Native.HookProc kbProc;
        static Native.HookProc msProc;
        static IntPtr kbHook = IntPtr.Zero;
        static IntPtr msHook = IntPtr.Zero;

        public static bool Install()
        {
            Uninstall();
            if (kbProc == null)
            {
                kbProc = KbCallback;
                msProc = MsCallback;
            }
            IntPtr mod = Native.GetModuleHandle(null);
            kbHook = Native.SetWindowsHookEx(Native.WH_KEYBOARD_LL, kbProc, mod, 0);
            msHook = Native.SetWindowsHookEx(Native.WH_MOUSE_LL, msProc, mod, 0);
            LastEventTick = Native.Now();
            return kbHook != IntPtr.Zero && msHook != IntPtr.Zero;
        }

        public static void Uninstall()
        {
            if (kbHook != IntPtr.Zero) { Native.UnhookWindowsHookEx(kbHook); kbHook = IntPtr.Zero; }
            if (msHook != IntPtr.Zero) { Native.UnhookWindowsHookEx(msHook); msHook = IntPtr.Zero; }
        }

        static IntPtr KbCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                LastEventTick = Native.Now();
                try
                {
                    Native.KBDLLHOOKSTRUCT k = (Native.KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(Native.KBDLLHOOKSTRUCT));
                    int msg = wParam.ToInt32();
                    bool down = msg == Native.WM_KEYDOWN || msg == Native.WM_SYSKEYDOWN;
                    bool up = msg == Native.WM_KEYUP || msg == Native.WM_SYSKEYUP;
                    bool injected = (k.flags & Native.LLKHF_INJECTED) != 0;
                    int id = (int)(k.vkCode & 0xFF);
                    if (OnButton != null && OnButton(id, down, up, injected)) return (IntPtr)1;
                }
                catch
                {
                    if (SwallowOnError) return (IntPtr)1;
                }
            }
            return Native.CallNextHookEx(kbHook, nCode, wParam, lParam);
        }

        static IntPtr MsCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                LastEventTick = Native.Now();
                try
                {
                    Native.MSLLHOOKSTRUCT m = (Native.MSLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(Native.MSLLHOOKSTRUCT));
                    int msg = wParam.ToInt32();
                    bool injected = (m.flags & Native.LLMHF_INJECTED) != 0;
                    int id = 0;
                    bool down = false;
                    switch (msg)
                    {
                        case Native.WM_LBUTTONDOWN: id = 1001; down = true; break;
                        case Native.WM_LBUTTONUP: id = 1001; break;
                        case Native.WM_RBUTTONDOWN: id = 1002; down = true; break;
                        case Native.WM_RBUTTONUP: id = 1002; break;
                        case Native.WM_MBUTTONDOWN: id = 1003; down = true; break;
                        case Native.WM_MBUTTONUP: id = 1003; break;
                        case Native.WM_XBUTTONDOWN:
                        case Native.WM_XBUTTONUP:
                            id = (((m.mouseData >> 16) & 0xFFFF) == 1) ? 1004 : 1005;
                            down = msg == Native.WM_XBUTTONDOWN;
                            break;
                    }
                    bool swallow;
                    if (id != 0) swallow = OnButton != null && OnButton(id, down, !down, injected);
                    else swallow = OnMotion != null && OnMotion(msg == Native.WM_MOUSEMOVE, injected);
                    if (swallow) return (IntPtr)1;
                }
                catch
                {
                    if (SwallowOnError) return (IntPtr)1;
                }
            }
            return Native.CallNextHookEx(msHook, nCode, wParam, lParam);
        }
    }

    // 4. Config
    class Config
    {
        public HashSet<int> Chord = new HashSet<int>();       // unlock combo
        public HashSet<int> LockChord = new HashSet<int>();   // optional lock key, empty = off
        public int ComboWindowMs = 1000;                       // all combo keys pressed within this
        public int IdleSeconds = 300;                          // 0 = off
        public int StrikeLimit = 10;                           // 0 = off
        public int StrikeWindowSeconds = 60;
        public bool PhantomMouse = false;                      // cursor moves while frozen, clicks still blocked
        public bool FreezeOnStart = true;
        public int AfterWindowsUnlock = 1;                     // 0 leave as it was, 1 freeze, 2 unfreeze
        public int TestSeconds = 60;
        public bool Debug = false;

        public static string Dir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Names.App); } }
        public static string InstalledExe { get { return Path.Combine(Dir, Names.App + ".exe"); } }
        public static string IniPath { get { return Path.Combine(Dir, "freeze.ini"); } }
        public static string StatePath { get { return Path.Combine(Dir, "freeze.state"); } }
        public static string LogPath { get { return Path.Combine(Path.Combine(Dir, "logs"), "freeze-debug.log"); } }

        public bool IsValid { get { return HasKeyAndMouse(Chord); } }

        public static DateTime Stamp()
        {
            try { return File.GetLastWriteTimeUtc(IniPath); }
            catch { return DateTime.MinValue; }
        }

        public static bool HasKeyAndMouse(IEnumerable<int> set)
        {
            bool key = false, mouse = false;
            foreach (int id in set)
            {
                if (id >= 1000) mouse = true; else key = true;
            }
            return key && mouse;
        }

        // a single key is only allowed if it's not one you'd type with
        public static bool ValidLockKey(HashSet<int> set)
        {
            if (set.Count >= 2) return true;
            if (set.Count != 1) return false;
            foreach (int id in set)
            {
                if (id == 0x13 || id == 0x91 || id == 1004 || id == 1005) return true;   // Pause, Scroll Lock, side buttons
                if (id >= 0x7C && id <= 0x87) return true;                                // F13-F24
            }
            return false;
        }

        public static Config Load()
        {
            Config c = new Config();
            if (!File.Exists(IniPath)) return c;
            string[] lines;
            try { lines = File.ReadAllLines(IniPath); }
            catch { return c; }
            bool sawAfterUnlock = false;
            foreach (string raw in lines)
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith(";") || line.StartsWith("#")) continue;
                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string k = line.Substring(0, eq).Trim().ToLowerInvariant();
                string v = line.Substring(eq + 1).Trim();
                switch (k)
                {
                    case "chord": c.Chord = ParseChord(v); break;
                    case "lockkey": c.LockChord = ParseChord(v); break;
                    case "combowindowms": c.ComboWindowMs = ParseInt(v, c.ComboWindowMs, 200, 5000); break;
                    case "idleseconds":
                        c.IdleSeconds = ParseInt(v, c.IdleSeconds, 0, 86400);
                        if (c.IdleSeconds > 0 && c.IdleSeconds < 10) c.IdleSeconds = 10;
                        break;
                    case "strikelimit": c.StrikeLimit = ParseInt(v, c.StrikeLimit, 0, 1000); break;
                    case "strikewindowseconds": c.StrikeWindowSeconds = ParseInt(v, c.StrikeWindowSeconds, 1, 3600); break;
                    case "phantommouse": c.PhantomMouse = ParseBool(v, c.PhantomMouse); break;
                    case "freezeonstart": c.FreezeOnStart = ParseBool(v, c.FreezeOnStart); break;
                    case "afterwindowsunlock": c.AfterWindowsUnlock = ParseInt(v, c.AfterWindowsUnlock, 0, 2); sawAfterUnlock = true; break;
                    case "freezeonunlock": if (!sawAfterUnlock) c.AfterWindowsUnlock = ParseBool(v, true) ? 1 : 0; break; // old name
                    case "testseconds": c.TestSeconds = ParseInt(v, c.TestSeconds, 5, 3600); break;
                    case "debug": c.Debug = ParseBool(v, c.Debug); break;
                }
            }
            return c;
        }

        public string Save()
        {
            string[] lines =
            {
                "; freezeMe-Security settings. Easiest to change from the Start menu: freezeMe-Security",
                "Chord=" + Encode(Chord),
                "; optional key combo that freezes straight away, blank = off",
                "LockKey=" + Encode(LockChord),
                "; all combo keys have to be pressed within this many ms",
                "ComboWindowMs=" + ComboWindowMs,
                "; seconds of no input before freezing (0 = off)",
                "IdleSeconds=" + IdleSeconds,
                "; wrong presses within StrikeWindowSeconds that lock Windows (0 = off)",
                "StrikeLimit=" + StrikeLimit,
                "StrikeWindowSeconds=" + StrikeWindowSeconds,
                "; 1 = cursor still moves while frozen (clicks still blocked)",
                "PhantomMouse=" + (PhantomMouse ? 1 : 0),
                "; freeze as soon as you sign in",
                "FreezeOnStart=" + (FreezeOnStart ? 1 : 0),
                "; after you unlock Windows: 0 = leave as it was, 1 = freeze, 2 = unfreeze (password is enough)",
                "AfterWindowsUnlock=" + AfterWindowsUnlock,
                "; how long --test stays frozen",
                "TestSeconds=" + TestSeconds,
                "; 1 = write logs\\freeze-debug.log (logs keys pressed while frozen)",
                "Debug=" + (Debug ? 1 : 0)
            };
            try
            {
                Directory.CreateDirectory(Dir);
                File.WriteAllLines(IniPath, lines);
                return null;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        static string Encode(IEnumerable<int> set)
        {
            List<string> parts = new List<string>();
            foreach (int id in Sorted(set)) parts.Add(id >= 1000 ? "M" + (id - 1000) : "K" + id);
            return string.Join(",", parts.ToArray());
        }

        static HashSet<int> ParseChord(string v)
        {
            HashSet<int> set = new HashSet<int>();
            foreach (string raw in v.Split(new char[] { ',', ' ', '+' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string t = raw.Trim().ToUpperInvariant();
                if (t.Length < 2) continue;
                int n;
                if (!int.TryParse(t.Substring(1), out n)) continue;
                if (t[0] == 'K' && n > 0 && n < 256) set.Add(n);
                else if (t[0] == 'M' && n >= 1 && n <= 5) set.Add(1000 + n);
            }
            return set;
        }

        static int ParseInt(string v, int def, int min, int max)
        {
            int n;
            if (!int.TryParse(v.Trim(), out n)) return def;
            if (n < min) n = min;
            if (n > max) n = max;
            return n;
        }

        static bool ParseBool(string v, bool def)
        {
            v = v.Trim().ToLowerInvariant();
            if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
            if (v == "0" || v == "false" || v == "no" || v == "off") return false;
            return def;
        }

        public static List<int> Sorted(IEnumerable<int> set)
        {
            List<int> l = new List<int>(set);
            l.Sort();
            return l;
        }

        public static string Describe(IEnumerable<int> set)
        {
            List<string> names = new List<string>();
            foreach (int id in Sorted(set)) names.Add(Name(id));
            if (names.Count == 0) return "(none)";
            return string.Join(" + ", names.ToArray());
        }

        public static string Name(int id)
        {
            switch (id)
            {
                case 1001: return "Left click";
                case 1002: return "Right click";
                case 1003: return "Middle click";
                case 1004: return "Mouse back";
                case 1005: return "Mouse forward";
                case 0xA0: return "Left Shift";
                case 0xA1: return "Right Shift";
                case 0xA2: return "Left Ctrl";
                case 0xA3: return "Right Ctrl";
                case 0xA4: return "Left Alt";
                case 0xA5: return "Right Alt";
                case 0x5B: return "Left Win";
                case 0x5C: return "Right Win";
                case 0x5D: return "Menu key";
                case 0x91: return "Scroll Lock";
                case 0x13: return "Pause";
                case 0x2D: return "Insert";
                case 0xDE: return "# (UK/IE)";
            }
            return ((Keys)id).ToString();
        }
    }

    // 5. State
    static class State
    {
        public static void Write(bool frozen)
        {
            try { File.WriteAllText(Config.StatePath, Program.Pid + " " + (frozen ? "1" : "0")); }
            catch { }
        }

        public static bool Read(out int pid, out bool frozen)
        {
            pid = 0;
            frozen = false;
            try
            {
                string[] p = File.ReadAllText(Config.StatePath).Trim().Split(' ');
                if (p.Length < 2) return false;
                pid = int.Parse(p[0]);
                frozen = p[1] == "1";
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    // 6. Log
    // Only used when Debug=1. Add() just queues (safe in the hook), Flush() writes from the timer.
    static class Log
    {
        public static bool Enabled;
        static readonly Queue<string> queue = new Queue<string>();

        public static void Add(string s)
        {
            if (!Enabled || queue.Count > 5000) return;
            queue.Enqueue(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "  " + s);
        }

        public static void Flush()
        {
            if (queue.Count == 0) return;
            string text = string.Join(Environment.NewLine, queue.ToArray()) + Environment.NewLine;
            queue.Clear();
            Write(text);
        }

        public static void WriteNow(string s)
        {
            Write(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "  " + s + Environment.NewLine);
        }

        static void Write(string text)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Config.LogPath));
                FileInfo fi = new FileInfo(Config.LogPath);
                if (fi.Exists && fi.Length > 1024 * 1024)
                {
                    string old = Config.LogPath + ".old";
                    if (File.Exists(old)) File.Delete(old);
                    File.Move(Config.LogPath, old);
                }
                File.AppendAllText(Config.LogPath, text);
            }
            catch { }
        }
    }

    // 7. Program
    static class Program
    {
        public static readonly int Pid = Process.GetCurrentProcess().Id;

        [STAThread]
        static int Main(string[] args)
        {
            string mode = args.Length > 0 ? args[0].Trim().ToLowerInvariant() : "";

            if (mode == "--stop") return Stop();
            if (mode == "--spawn-watchdog")
            {
                // middleman so the watchdog isn't a child of main (End process tree won't get both)
                SpawnDetached("--watchdog " + (args.Length > 1 ? args[1] : "0"));
                return 0;
            }
            if (mode == "--watchdog")
            {
                int pid = 0;
                if (args.Length > 1) int.TryParse(args[1], out pid);
                return Watchdog.Run(pid);
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (mode == "--setup" || mode == "--remove-task")
            {
                if (!IsAdmin()) return 5;
                if (mode == "--remove-task") return Setup.RemoveTask();
                bool silent = args.Length > 1 && args[1].Trim().ToLowerInvariant() == "--silent";
                return Setup.Run(silent);
            }

            if (mode == "") mode = "--settings"; // double-click opens the settings window

            if (mode == "--enrol" || mode == "--enroll" || mode == "--settings")
            {
                if (!IsAdmin())
                {
                    RelaunchElevated(mode);
                    return 0;
                }
                if (mode == "--settings") Application.Run(new SettingsForm());
                else Application.Run(new EnrolForm(EnrolMode.Unlock, true));
                return 0;
            }

            // safe mode = way out if the combo is forgotten
            if (SystemInformation.BootMode != BootMode.Normal) return 0;

            if (mode != "--autostart" && mode != "--test" && mode != "--start-frozen" && mode != "--no-start-freeze")
            {
                MessageBox.Show("Unknown option: " + args[0], Names.App);
                return 2;
            }

            bool test = mode == "--test";
            Config cfg = Config.Load();
            if (!cfg.IsValid)
            {
                // no combo, no freeze
                if (test) MessageBox.Show("No unlock combo saved yet. Set one in the settings first.", Names.App);
                return 1;
            }

            bool createdNew;
            using (Mutex mx = new Mutex(true, test ? Names.TestMutex : Names.MainMutex, out createdNew))
            {
                if (!createdNew) return 0;
                try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.High; }
                catch { }

                EventWaitHandle stop = OpenOrCreateStop();
                if (!test && stop != null) stop.Reset();

                bool startFrozen = test || mode == "--start-frozen" || (cfg.FreezeOnStart && mode == "--autostart");
                Application.Run(new LockerForm(cfg, test, startFrozen, stop));
            }
            return 0;
        }

        // stop a running copy and wait (up to 6s) for it and the watchdog to exit
        public static void StopAndWait()
        {
            try { EventWaitHandle.OpenExisting(Names.StopEvent).Set(); }
            catch { return; }
            for (int i = 0; i < 30; i++)
            {
                if (!MutexExists(Names.MainMutex) && !MutexExists(Names.WatchdogMutex)) break;
                Thread.Sleep(200);
            }
            Thread.Sleep(300);
        }

        static int Stop()
        {
            try
            {
                EventWaitHandle ev = EventWaitHandle.OpenExisting(Names.StopEvent);
                ev.Set();
                return 0;
            }
            catch (WaitHandleCannotBeOpenedException)
            {
                return 0; // not running
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show("Run this as administrator to stop it.", Names.App);
                return 5;
            }
        }

        public static bool IsAdmin()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        static void RelaunchElevated(string arguments)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath, arguments);
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                Process.Start(psi);
            }
            catch { } // UAC cancelled
        }

        public static EventWaitHandle OpenOrCreateStop()
        {
            try { return new EventWaitHandle(false, EventResetMode.ManualReset, Names.StopEvent); }
            catch { return null; }
        }

        public static void SpawnDetached(string arguments)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath, arguments);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                Process.Start(psi);
            }
            catch { }
        }

        public static bool MutexExists(string name)
        {
            try
            {
                Mutex m;
                if (Mutex.TryOpenExisting(name, out m))
                {
                    m.Close();
                    return true;
                }
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return true; // exists but no access
            }
            catch
            {
                return false;
            }
        }

        public static bool ProcessAlive(int pid)
        {
            try
            {
                using (Process p = Process.GetProcessById(pid)) return !p.HasExited;
            }
            catch
            {
                return false;
            }
        }
    }

    // 7b. Setup (called by the installer)
    static class Setup
    {
        static string ShortcutPath { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), Names.App + ".lnk"); } }

        public static int Run(bool silent)
        {
            MigrateOldFreeze();
            if (!silent && !Config.Load().IsValid) Application.Run(new EnrolForm(EnrolMode.Unlock, true));
            SecureFiles();
            try { File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), Names.App + " Settings.lnk")); } catch { } // old name
            CreateShortcut(ShortcutPath, Application.ExecutablePath, "--settings");
            return RegisterTask();
        }

        public static bool IsInstalled()
        {
            return File.Exists(Config.InstalledExe) && Exec("schtasks.exe", "/query /tn \"" + Names.App + "\"") == 0;
        }

        public static bool IsRunning()
        {
            return Program.MutexExists(Names.MainMutex);
        }

        // copy this exe to Program Files (if it's not already running from there) and set it up.
        // returns null if it worked, otherwise what went wrong
        public static string Install()
        {
            Program.StopAndWait();
            string src = Path.GetFullPath(Application.ExecutablePath);
            string dst = Path.GetFullPath(Config.InstalledExe);
            try
            {
                Directory.CreateDirectory(Config.Dir);
                if (!string.Equals(src, dst, StringComparison.OrdinalIgnoreCase)) File.Copy(src, dst, true);
            }
            catch (Exception ex)
            {
                return "couldn't copy the exe: " + ex.Message;
            }
            int rc = Exec(dst, "--setup --silent");
            if (rc != 0) return "creating the sign-in task failed (code " + rc + ")";
            return null;
        }

        public static int StartNow()
        {
            return Exec("schtasks.exe", "/run /tn \"" + Names.App + "\"");
        }

        // returns true if this process should close (the uninstaller or the self-delete is taking over)
        public static bool Uninstall()
        {
            string unins = Path.Combine(Config.Dir, "unins000.exe");
            if (File.Exists(unins))
            {
                // installed with the setup exe: let its uninstaller do it
                try { Process.Start(unins); return true; } catch { }
            }
            Program.StopAndWait();
            RemoveTask();
            try { File.Delete(ShortcutPath); } catch { }
            try { File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), Names.App + " Settings.lnk")); } catch { }
            string here = Path.GetFullPath(Application.ExecutablePath);
            bool runningFromInstallDir = here.StartsWith(Path.GetFullPath(Config.Dir) + "\\", StringComparison.OrdinalIgnoreCase);
            if (runningFromInstallDir)
            {
                // can't delete our own exe while it's running, so cmd does it a few seconds after we close
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c timeout /t 3 /nobreak >nul & rmdir /s /q \"" + Config.Dir + "\"");
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                try { Process.Start(psi); } catch { }
                return true;
            }
            try { Directory.Delete(Config.Dir, true); } catch { }
            return false;
        }

        static void CreateShortcut(string lnkPath, string target, string arguments)
        {
            try
            {
                Type t = Type.GetTypeFromProgID("WScript.Shell");
                object shell = Activator.CreateInstance(t);
                object sc = t.InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { lnkPath });
                Type st = sc.GetType();
                st.InvokeMember("TargetPath", System.Reflection.BindingFlags.SetProperty, null, sc, new object[] { target });
                st.InvokeMember("Arguments", System.Reflection.BindingFlags.SetProperty, null, sc, new object[] { arguments });
                st.InvokeMember("IconLocation", System.Reflection.BindingFlags.SetProperty, null, sc, new object[] { target + ",0" });
                st.InvokeMember("Save", System.Reflection.BindingFlags.InvokeMethod, null, sc, null);
            }
            catch { }
        }

        public static int RemoveTask()
        {
            return Exec("schtasks.exe", "/delete /tn \"" + Names.App + "\" /f");
        }

        // the task: at sign-in, as this user, highest privileges, no time limit, also on battery
        static int RegisterTask()
        {
            string user = Environment.UserDomainName + "\\" + Environment.UserName;
            string exe = Application.ExecutablePath;
            string xml =
                "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" +
                "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n" +
                "  <RegistrationInfo><Author>tomas-docx</Author><Description>freezeMe-Security keyboard and mouse lock</Description></RegistrationInfo>\r\n" +
                "  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>" + Esc(user) + "</UserId></LogonTrigger></Triggers>\r\n" +
                "  <Principals><Principal id=\"Author\"><UserId>" + Esc(user) + "</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\r\n" +
                "  <Settings>\r\n" +
                "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n" +
                "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n" +
                "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n" +
                "    <AllowHardTerminate>true</AllowHardTerminate>\r\n" +
                "    <StartWhenAvailable>false</StartWhenAvailable>\r\n" +
                "    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n" +
                "    <Enabled>true</Enabled>\r\n" +
                "    <Hidden>false</Hidden>\r\n" +
                "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n" +
                "    <Priority>4</Priority>\r\n" +
                "    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\r\n" +
                "  </Settings>\r\n" +
                "  <Actions Context=\"Author\"><Exec><Command>" + Esc(exe) + "</Command><Arguments>--autostart</Arguments></Exec></Actions>\r\n" +
                "</Task>\r\n";
            string tmp = Path.Combine(Path.GetTempPath(), "freezeMe-Security-task.xml");
            try
            {
                File.WriteAllText(tmp, xml, Encoding.Unicode);
                return Exec("schtasks.exe", "/create /tn \"" + Names.App + "\" /xml \"" + tmp + "\" /f");
            }
            finally
            {
                try { File.Delete(tmp); } catch { }
            }
        }

        // combo file and logs readable by admins + SYSTEM only
        static void SecureFiles()
        {
            string logs = Path.GetDirectoryName(Config.LogPath);
            try { Directory.CreateDirectory(logs); } catch { }
            Exec("icacls.exe", "\"" + logs + "\" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F");
            if (File.Exists(Config.IniPath))
                Exec("icacls.exe", "\"" + Config.IniPath + "\" /inheritance:r /grant:r *S-1-5-32-544:F *S-1-5-18:F");
        }

        // old "Freeze" install from before the rename: stop it, keep its combo, remove it
        static void MigrateOldFreeze()
        {
            string oldDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Freeze");
            string oldExe = Path.Combine(oldDir, "Freeze.exe");
            if (!File.Exists(oldExe)) return;
            Exec(oldExe, "--stop");
            Thread.Sleep(2000);
            string oldIni = Path.Combine(oldDir, "freeze.ini");
            try { if (File.Exists(oldIni) && !File.Exists(Config.IniPath)) File.Copy(oldIni, Config.IniPath); } catch { }
            Exec("schtasks.exe", "/delete /tn Freeze /f");
            try { Directory.Delete(oldDir, true); } catch { }
        }

        static string Esc(string s)
        {
            return System.Security.SecurityElement.Escape(s);
        }

        public static int Exec(string file, string arguments)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(file, arguments);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                using (Process p = Process.Start(psi))
                {
                    if (!p.WaitForExit(30000)) return -1;
                    return p.ExitCode;
                }
            }
            catch
            {
                return -1;
            }
        }
    }

    // 8. Watchdog
    // if main dies while frozen: lock windows and restart it
    static class Watchdog
    {
        public static int Run(int mainPid)
        {
            bool createdNew;
            using (Mutex mx = new Mutex(true, Names.WatchdogMutex, out createdNew))
            {
                if (!createdNew) return 0;
                EventWaitHandle stop = Program.OpenOrCreateStop();
                int pid = mainPid;
                int quickDeaths = 0;

                while (true)
                {
                    uint watchingSince = Native.Now();
                    WaitForExit(pid, stop);
                    if (stop != null && stop.WaitOne(0)) return 0;
                    Thread.Sleep(300);
                    if (stop != null && stop.WaitOne(0)) return 0;

                    // another copy already running? watch that one
                    int otherPid;
                    bool otherFrozen;
                    if (Program.MutexExists(Names.MainMutex) && State.Read(out otherPid, out otherFrozen)
                        && otherPid != pid && Program.ProcessAlive(otherPid))
                    {
                        pid = otherPid;
                        continue;
                    }

                    int deadPid;
                    bool wasFrozen;
                    if (!State.Read(out deadPid, out wasFrozen)) wasFrozen = true; // unknown, assume frozen
                    if (Config.Load().Debug) Log.WriteNow("watchdog: main process died, frozen=" + wasFrozen);
                    if (wasFrozen) Native.LockWorkStation();

                    if (Native.Since(watchingSince) < 10000) quickDeaths++; else quickDeaths = 0;
                    if (quickDeaths >= 3) return 2; // keeps dying, give up

                    try
                    {
                        ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath, wasFrozen ? "--start-frozen" : "--no-start-freeze");
                        psi.UseShellExecute = false;
                        Process p = Process.Start(psi);
                        pid = p.Id;
                    }
                    catch
                    {
                        return 3;
                    }
                    Thread.Sleep(1500);
                }
            }
        }

        static void WaitForExit(int pid, EventWaitHandle stop)
        {
            Process p;
            try { p = Process.GetProcessById(pid); }
            catch { return; }
            using (p)
            {
                while (true)
                {
                    try
                    {
                        if (p.WaitForExit(500)) return;
                    }
                    catch
                    {
                        return;
                    }
                    if (stop != null && stop.WaitOne(0)) return;
                }
            }
        }
    }

    // 9. LockerForm
    class LockerForm : Form
    {
        Config cfg;
        DateTime cfgStamp;
        readonly bool test;
        readonly bool startFrozen;
        readonly EventWaitHandle stop;
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();

        bool initDone, frozen, sessionLocked, tripArmed, pendingLock, watchdogSeen, closing;
        bool desktopWasDefault = true;
        uint frozenAt, unfrozenAt, activityFloor, lastLockCall;
        uint lastWatchdogCheck, lastConfigCheck, lastPrune, lastFlush, lastSessionCheck;
        int lockCalls, lockedPolls, unlockedPolls;

        readonly Dictionary<int, uint> held = new Dictionary<int, uint>();  // held now -> when it went down
        readonly HashSet<int> swallowedDowns = new HashSet<int>();          // downs we swallowed
        readonly HashSet<int> swallowUps = new HashSet<int>();              // combo keys still down at unlock
        readonly Queue<uint> strikes = new Queue<uint>();

        public LockerForm(Config cfg, bool test, bool startFrozen, EventWaitHandle stop)
        {
            this.cfg = cfg;
            this.test = test;
            this.startFrozen = startFrozen;
            this.stop = stop;
            cfgStamp = Config.Stamp();
            Log.Enabled = cfg.Debug;
            ShowInTaskbar = false;
            FormBorderStyle = FormBorderStyle.None;
            timer.Interval = 100;
            timer.Tick += OnTick;
            uint now = Native.Now();
            activityFloor = now;
            lastWatchdogCheck = now;
            lastConfigCheck = now;
            lastPrune = now;
            lastFlush = now;
            lastSessionCheck = now;
            lastLockCall = unchecked(now - 10000u);
        }

        // hidden, only here for session lock/unlock messages
        protected override void SetVisibleCore(bool value)
        {
            if (!IsHandleCreated) CreateHandle();
            base.SetVisibleCore(false);
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            if (initDone) return;
            initDone = true;

            Native.WTSRegisterSessionNotification(Handle, 0);
            Hooks.OnButton = OnButton;
            Hooks.OnMotion = OnMotion;
            Hooks.Install();
            Log.Add("started" + (test ? " (test)" : ""));

            if (startFrozen) Freeze("start");
            else if (!test) State.Write(false);

            if (!test) Program.SpawnDetached("--spawn-watchdog " + Program.Pid);
            timer.Start();
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == Native.WM_WTSSESSION_CHANGE)
            {
                int code = m.WParam.ToInt32();
                if (code == Native.WTS_SESSION_LOCK)
                {
                    sessionLocked = true;
                    pendingLock = false;
                    lockedPolls = 0;
                    unlockedPolls = 0;
                    Log.Add("windows locked");
                }
                else if (code == Native.WTS_SESSION_UNLOCK)
                {
                    OnWindowsUnlocked("message");
                }
            }
            base.WndProc(ref m);
        }

        void OnWindowsUnlocked(string how)
        {
            sessionLocked = false;
            pendingLock = false;
            activityFloor = Native.Now();
            Log.Add("windows unlocked (" + how + ")");
            if (test)
            {
                if (frozen) Freeze("after windows unlock");
                return;
            }
            if (cfg.AfterWindowsUnlock == 2)
            {
                if (frozen) Unfreeze("windows password");
            }
            else if (cfg.AfterWindowsUnlock == 1 || frozen)
            {
                Freeze("after windows unlock");
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // sign out / shutdown, tell the watchdog not to restart us
            if (e.CloseReason == CloseReason.WindowsShutDown && stop != null && !test)
            {
                try { stop.Set(); } catch { }
            }
            base.OnFormClosing(e);
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            timer.Stop();
            Hooks.Uninstall();
            try { Native.WTSUnRegisterSessionNotification(Handle); } catch { }
            if (!test) State.Write(false);
            Log.Add("exit");
            Log.Flush();
            base.OnFormClosed(e);
        }

        void OnTick(object sender, EventArgs e)
        {
            if (closing) return;

            if (stop != null && stop.WaitOne(0))
            {
                Log.Add("stopped");
                closing = true;
                Close();
                return;
            }

            uint now = Native.Now();
            if (Native.Since(lastFlush) > 1000) { lastFlush = now; Log.Flush(); }
            if (Native.Since(lastConfigCheck) > 2000) { lastConfigCheck = now; ReloadConfig(); }
            if (Native.Since(lastPrune) > 5000) { lastPrune = now; PruneHeld(now); }

            bool normalDesktop = Native.InputDesktopIsDefault();

            // backup for a missed lock/unlock message. needs 2 checks in a row either way,
            // and never counts as locked while the normal desktop is showing.
            if (Native.Since(lastSessionCheck) > 1000)
            {
                lastSessionCheck = now;
                int ls = Native.SessionLockState();
                if (!sessionLocked)
                {
                    unlockedPolls = 0;
                    if (ls == 1 && !normalDesktop) lockedPolls++; else lockedPolls = 0;
                    if (lockedPolls >= 2)
                    {
                        lockedPolls = 0;
                        sessionLocked = true;
                        pendingLock = false;
                        Log.Add("windows locked (polled)");
                    }
                }
                else
                {
                    lockedPolls = 0;
                    if (normalDesktop && ls != 1) unlockedPolls++; else unlockedPolls = 0;
                    if (unlockedPolls >= 2)
                    {
                        unlockedPolls = 0;
                        OnWindowsUnlocked("polled");
                    }
                }
            }

            if (frozen)
            {
                if (test && Native.Since(frozenAt) >= cfg.TestSeconds * 1000)
                {
                    Unfreeze("test time up");
                    return;
                }

                if (!sessionLocked)
                {
                    if (normalDesktop)
                    {
                        if (!tripArmed)
                        {
                            tripArmed = true;
                            Hooks.LastEventTick = Native.Now();
                        }
                        else
                        {
                            // input got past the hooks (windows can drop them), rehook + lock
                            int gap = unchecked((int)(Native.LastInputTick() - Hooks.LastEventTick));
                            if (gap > 1500)
                            {
                                Hooks.Install();
                                RequestLock("input got past the hook");
                            }
                            else if (pendingLock)
                            {
                                // came back from Ctrl+Alt+Del without locking (Cancel / Task Manager)
                                if (!desktopWasDefault) CallLock("back from secure screen");
                                else if (Native.Since(lastLockCall) > 3000 && lockCalls < 5) CallLock("retry");
                            }
                        }
                    }
                    else if (tripArmed && !pendingLock)
                    {
                        RequestLock("Ctrl+Alt+Del or secure screen");
                    }
                }
            }
            else
            {
                if (test)
                {
                    // wait for combo keys to be released
                    if (swallowUps.Count == 0 || Native.Since(unfrozenAt) > 3000)
                    {
                        closing = true;
                        Close();
                    }
                    return;
                }

                if (cfg.IdleSeconds > 0 && !sessionLocked)
                {
                    int idle = Math.Min(Native.Since(Native.LastInputTick()), Native.Since(activityFloor));
                    if (idle >= cfg.IdleSeconds * 1000) Freeze("idle");
                }
            }

            desktopWasDefault = normalDesktop;

            if (!test && Native.Since(lastWatchdogCheck) > 2000)
            {
                lastWatchdogCheck = Native.Now();
                CheckWatchdog();
            }
        }

        void ReloadConfig()
        {
            DateTime st = Config.Stamp();
            if (st == cfgStamp) return;
            cfgStamp = st;
            Config n = Config.Load();
            if (!n.IsValid) n.Chord = cfg.Chord; // never end up with no way to unlock
            cfg = n;
            Log.Enabled = cfg.Debug;
            Log.Add("settings reloaded");
        }

        void PruneHeld(uint now)
        {
            List<int> old = null;
            foreach (KeyValuePair<int, uint> kv in held)
            {
                if (unchecked((int)(now - kv.Value)) > 60000)
                {
                    if (old == null) old = new List<int>();
                    old.Add(kv.Key);
                }
            }
            if (old != null) foreach (int id in old) held.Remove(id);
        }

        void CheckWatchdog()
        {
            if (Program.MutexExists(Names.WatchdogMutex))
            {
                watchdogSeen = true;
                return;
            }
            if (watchdogSeen && frozen) RequestLock("watchdog killed");
            watchdogSeen = false;
            Program.SpawnDetached("--spawn-watchdog " + Program.Pid);
        }

        void Freeze(string reason)
        {
            frozen = true;
            frozenAt = Native.Now();
            tripArmed = false;
            pendingLock = false;
            held.Clear();
            swallowedDowns.Clear();
            swallowUps.Clear();
            strikes.Clear();
            Hooks.SwallowOnError = true;
            Log.Add("FROZEN: " + reason);
            if (!test) BeginInvoke(new Action(delegate { State.Write(true); }));
        }

        void Unfreeze(string reason)
        {
            frozen = false;
            pendingLock = false;
            Hooks.SwallowOnError = false;
            swallowUps.Clear();
            swallowUps.UnionWith(held.Keys);
            held.Clear();
            swallowedDowns.Clear();
            strikes.Clear();
            activityFloor = Native.Now();
            unfrozenAt = Native.Now();
            Log.Add("UNFROZEN: " + reason);
            if (!test) BeginInvoke(new Action(delegate { State.Write(false); }));
        }

        void RequestLock(string reason)
        {
            if (sessionLocked) return;
            pendingLock = true;
            lockCalls = 0;
            CallLock(reason);
        }

        void CallLock(string reason)
        {
            lastLockCall = Native.Now();
            lockCalls++;
            Log.Add("windows lock: " + reason);
            Native.LockWorkStation();
        }

        void Strike(uint now, int id)
        {
            if (cfg.StrikeLimit <= 0) return;
            strikes.Enqueue(now);
            while (strikes.Count > 0 && unchecked((int)(now - strikes.Peek())) > cfg.StrikeWindowSeconds * 1000) strikes.Dequeue();
            if (Log.Enabled) Log.Add("wrong press " + Config.Name(id) + " (" + strikes.Count + "/" + cfg.StrikeLimit + ")");
            if (strikes.Count >= cfg.StrikeLimit)
            {
                strikes.Clear();
                BeginInvoke(new Action(delegate { RequestLock(cfg.StrikeLimit + " wrong presses"); }));
            }
        }

        // true if the keys pressed in the last ComboWindowMs are exactly this combo.
        // older held keys are ignored, so a stuck or stray key times out on its own.
        bool RecentMatches(HashSet<int> combo, uint now)
        {
            if (combo.Count == 0) return false;
            int n = 0;
            foreach (KeyValuePair<int, uint> kv in held)
            {
                if (unchecked((int)(now - kv.Value)) > cfg.ComboWindowMs) continue;
                if (!combo.Contains(kv.Key)) return false;
                n++;
            }
            return n == combo.Count;
        }

        // hook callback
        bool OnButton(int id, bool down, bool up, bool injected)
        {
            if (sessionLocked) return false; // never touch the lock screen

            uint now = Native.Now();

            if (!frozen)
            {
                if (up)
                {
                    held.Remove(id);
                    return swallowUps.Remove(id);
                }
                if (down)
                {
                    swallowUps.Remove(id);
                    if (injected || held.ContainsKey(id)) return false;
                    held[id] = now;
                    if (RecentMatches(cfg.LockChord, now))
                    {
                        Freeze("lock key");
                        swallowedDowns.Add(id); // eat this key's up too
                        return true;
                    }
                }
                return false;
            }

            if (injected) return true; // ignore SendInput etc

            if (down)
            {
                swallowedDowns.Add(id);
                if (held.ContainsKey(id)) return true; // autorepeat
                held[id] = now;
                if (Log.Enabled) Log.Add("down " + Config.Name(id));
                if (RecentMatches(cfg.Chord, now))
                {
                    Unfreeze("combo");
                    return true;
                }
                if (!cfg.Chord.Contains(id)) Strike(now, id);
                return true;
            }

            if (up)
            {
                held.Remove(id);
                bool ours = swallowedDowns.Remove(id);
                // letting go of a stray key can leave exactly the combo held
                if (!cfg.Chord.Contains(id) && RecentMatches(cfg.Chord, now)) Unfreeze("combo");
                return ours; // not ours = pressed before the freeze, let it through
            }

            return true;
        }

        bool OnMotion(bool isMove, bool injected)
        {
            if (sessionLocked || !frozen) return false;
            if (isMove && cfg.PhantomMouse && !injected) return false; // phantom mouse: moves, does nothing
            return true;
        }
    }

    // 10. EnrolForm
    enum EnrolMode { Unlock, LockKey }

    class EnrolForm : Form
    {
        public HashSet<int> Result;

        readonly EnrolMode mode;
        readonly bool saveDirectly;
        readonly Label label = new Label();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly HashSet<int> current = new HashSet<int>();
        readonly HashSet<int> biggest = new HashSet<int>();
        readonly HashSet<int> swallowed = new HashSet<int>();
        HashSet<int> first;
        uint lastInput, finishedAt;
        bool finished;

        string Intro
        {
            get
            {
                if (mode == EnrolMode.Unlock)
                    return "Press your UNLOCK combo (keys + at least one mouse button)\nwithin about a second, hold it, then let go.\n\nEsc to cancel.";
                return "Press your LOCK key combo (e.g. Ctrl + #), then let go.\n\nEsc to cancel.";
            }
        }

        public EnrolForm(EnrolMode mode, bool saveDirectly)
        {
            this.mode = mode;
            this.saveDirectly = saveDirectly;
            Text = Names.App + (mode == EnrolMode.Unlock ? " - unlock combo" : " - lock key");
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(720, 320);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            TopMost = true;

            label.Dock = DockStyle.Fill;
            label.Font = new Font("Segoe UI", 13f);
            label.TextAlign = ContentAlignment.MiddleCenter;
            label.Padding = new Padding(20);
            label.Text = Intro;
            Controls.Add(label);

            timer.Interval = 250;
            timer.Tick += OnTick;
            lastInput = Native.Now();
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Hooks.SwallowOnError = false;
            Hooks.OnButton = OnButton;
            Hooks.OnMotion = delegate(bool isMove, bool injected) { return false; };
            if (!Hooks.Install()) label.Text = "Couldn't hook the keyboard and mouse.\nRun this as administrator.";
            Activate();
            timer.Start();
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            timer.Stop();
            Hooks.Uninstall();
            base.OnFormClosed(e);
        }

        void OnTick(object sender, EventArgs e)
        {
            if (finished)
            {
                if (Native.Since(finishedAt) > (saveDirectly ? 4000 : 1200))
                {
                    if (!saveDirectly) DialogResult = DialogResult.OK;
                    Close();
                }
                return;
            }
            if (Native.Since(lastInput) > 120000) Close(); // 2 min timeout
        }

        // swallow presses so win key etc don't fire while enrolling
        bool OnButton(int id, bool down, bool up, bool injected)
        {
            if (finished) return false;

            if (injected)
            {
                if (down)
                {
                    BeginInvoke(new Action(delegate
                    {
                        label.Text = "That one came from software (mouse app / macro), not the device.\nPick a different key or button.\n\n" + Intro;
                    }));
                }
                return false;
            }

            lastInput = Native.Now();

            if (down)
            {
                if (current.Count == 0 && biggest.Count == 0 && id == 0x1B)
                {
                    swallowed.Add(id);
                    BeginInvoke(new Action(Close));
                    return true;
                }
                current.Add(id);
                biggest.Add(id);
                swallowed.Add(id);
                string live = "Holding: " + Config.Describe(biggest);
                BeginInvoke(new Action(delegate { label.Text = live; }));
                return true;
            }

            if (up)
            {
                current.Remove(id);
                if (current.Count == 0 && biggest.Count > 0)
                {
                    HashSet<int> got = new HashSet<int>(biggest);
                    biggest.Clear();
                    BeginInvoke(new Action(delegate { Captured(got); }));
                }
                return swallowed.Remove(id);
            }

            return false;
        }

        void Captured(HashSet<int> got)
        {
            if (mode == EnrolMode.Unlock && !Config.HasKeyAndMouse(got))
            {
                label.Text = "Got: " + Config.Describe(got) + "\n\nNeeds at least one KEYBOARD key AND one MOUSE button.\nTry again.";
                return;
            }
            if (mode == EnrolMode.LockKey && !Config.ValidLockKey(got))
            {
                label.Text = "Got: " + Config.Describe(got) + "\n\nUse 2+ keys (e.g. Ctrl + #). A single key only works for\nPause, Scroll Lock, F13-F24 or a mouse side button.\nTry again.";
                return;
            }
            if (first == null)
            {
                first = got;
                label.Text = "Got: " + Config.Describe(got) + "\n\nDo it again to confirm.";
                return;
            }
            if (!first.SetEquals(got))
            {
                first = null;
                label.Text = "Didn't match the first one. Start again.\n\n" + Intro;
                return;
            }

            if (saveDirectly)
            {
                Config cfg = Config.Load();
                if (mode == EnrolMode.Unlock) cfg.Chord = new HashSet<int>(first);
                else cfg.LockChord = new HashSet<int>(first);
                string err = cfg.Save();
                if (err != null)
                {
                    first = null;
                    label.Text = "Couldn't save: " + err + "\n\nRun this as administrator.";
                    return;
                }
            }

            Result = new HashSet<int>(first);
            finished = true;
            finishedAt = Native.Now();
            label.Text = (saveDirectly ? "Saved: " : "Got it: ") + Config.Describe(first);
        }
    }

    // 11. SettingsForm
    class SettingsForm : Form
    {
        readonly Config cfg;
        HashSet<int> chord;
        HashSet<int> lockChord;

        readonly Label chordLabel = new Label();
        readonly Label lockLabel = new Label();
        readonly NumericUpDown comboWindow = Num(200, 5000, 100);
        readonly NumericUpDown idle = Num(0, 86400, 30);
        readonly NumericUpDown strikeLimit = Num(0, 100, 1);
        readonly NumericUpDown strikeWindow = Num(1, 3600, 10);
        readonly NumericUpDown testSeconds = Num(5, 3600, 5);
        readonly ComboBox afterUnlock = new ComboBox();
        readonly CheckBox freezeOnStart = new CheckBox();
        readonly CheckBox phantom = new CheckBox();
        readonly CheckBox debug = new CheckBox();
        readonly Label status = new Label();

        public SettingsForm()
        {
            cfg = Config.Load();
            chord = new HashSet<int>(cfg.Chord);
            lockChord = new HashSet<int>(cfg.LockChord);

            Text = Names.App + " settings";
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Font = new Font("Segoe UI", 10f);
            Padding = new Padding(12);

            afterUnlock.DropDownStyle = ComboBoxStyle.DropDownList;
            afterUnlock.Width = 260;
            afterUnlock.Items.Add("Leave it as it was");
            afterUnlock.Items.Add("Freeze");
            afterUnlock.Items.Add("Unfreeze (password is enough)");

            freezeOnStart.Text = "Freeze when I sign in";
            phantom.Text = "Phantom mouse (cursor moves while frozen, clicks do nothing)";
            debug.Text = "Debug log (logs\\freeze-debug.log, includes keys pressed while frozen)";
            foreach (CheckBox c in new CheckBox[] { freezeOnStart, phantom, debug }) c.AutoSize = true;
            chordLabel.AutoSize = true;
            lockLabel.AutoSize = true;

            TableLayoutPanel t = new TableLayoutPanel();
            t.ColumnCount = 2;
            t.AutoSize = true;
            t.AutoSizeMode = AutoSizeMode.GrowAndShrink;

            status.AutoSize = true;
            status.Font = new Font(Font, FontStyle.Bold);
            Row(t, "Status", status);
            Row(t, "", Line(Btn("Install / update", OnInstall), Btn("Start now", OnStart), Btn("Test", OnTest), Btn("Uninstall", OnUninstall)));
            Row(t, "Unlock combo", Line(chordLabel, Btn("Change...", ChangeChord)));
            Row(t, "Lock key", Line(lockLabel, Btn("Set...", SetLockKey), Btn("Clear", ClearLockKey)));
            Row(t, "Combo window (ms)", comboWindow);
            Row(t, "Lock after idle (seconds, 0 = off)", idle);
            Row(t, "Wrong presses before Windows lock (0 = off)", strikeLimit);
            Row(t, "...counted over (seconds)", strikeWindow);
            Row(t, "After I unlock Windows", afterUnlock);
            Row(t, "", freezeOnStart);
            Row(t, "", phantom);
            Row(t, "Test mode length (seconds)", testSeconds);
            Row(t, "", debug);
            Row(t, "", Line(Btn("Save", OnSave), Btn("Close", delegate { Close(); })));
            Controls.Add(t);

            comboWindow.Value = cfg.ComboWindowMs;
            idle.Value = cfg.IdleSeconds;
            strikeLimit.Value = Math.Min(cfg.StrikeLimit, 100);
            strikeWindow.Value = cfg.StrikeWindowSeconds;
            testSeconds.Value = cfg.TestSeconds;
            afterUnlock.SelectedIndex = cfg.AfterWindowsUnlock;
            freezeOnStart.Checked = cfg.FreezeOnStart;
            phantom.Checked = cfg.PhantomMouse;
            debug.Checked = cfg.Debug;
            UpdateLabels();
            UpdateStatus();
        }

        static NumericUpDown Num(int min, int max, int step)
        {
            NumericUpDown n = new NumericUpDown();
            n.Minimum = min;
            n.Maximum = max;
            n.Increment = step;
            n.Width = 100;
            return n;
        }

        static Button Btn(string text, EventHandler onClick)
        {
            Button b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.Click += onClick;
            return b;
        }

        static FlowLayoutPanel Line(params Control[] controls)
        {
            FlowLayoutPanel p = new FlowLayoutPanel();
            p.AutoSize = true;
            p.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            p.WrapContents = false;
            p.Margin = new Padding(0);
            foreach (Control c in controls)
            {
                c.Anchor = AnchorStyles.Left;
                p.Controls.Add(c);
            }
            return p;
        }

        static void Row(TableLayoutPanel t, string text, Control c)
        {
            Label l = new Label();
            l.Text = text;
            l.AutoSize = true;
            l.Anchor = AnchorStyles.Left;
            l.Margin = new Padding(3, 8, 12, 3);
            t.Controls.Add(l);
            c.Anchor = AnchorStyles.Left;
            t.Controls.Add(c);
        }

        void UpdateLabels()
        {
            chordLabel.Text = Config.Describe(chord);
            lockLabel.Text = lockChord.Count == 0 ? "(off)" : Config.Describe(lockChord);
        }

        void ChangeChord(object sender, EventArgs e)
        {
            using (EnrolForm f = new EnrolForm(EnrolMode.Unlock, false))
            {
                if (f.ShowDialog(this) == DialogResult.OK && f.Result != null) chord = f.Result;
            }
            UpdateLabels();
        }

        void SetLockKey(object sender, EventArgs e)
        {
            using (EnrolForm f = new EnrolForm(EnrolMode.LockKey, false))
            {
                if (f.ShowDialog(this) == DialogResult.OK && f.Result != null) lockChord = f.Result;
            }
            UpdateLabels();
        }

        void ClearLockKey(object sender, EventArgs e)
        {
            lockChord = new HashSet<int>();
            UpdateLabels();
        }

        void UpdateStatus()
        {
            bool installed = Setup.IsInstalled();
            bool running = Setup.IsRunning();
            status.Text = (installed ? "Installed" : "Not installed") + ", " + (running ? "running" : "not running");
        }

        // saves the form to freeze.ini. false if it didn't
        bool SaveSettings()
        {
            if (!Config.HasKeyAndMouse(chord))
            {
                MessageBox.Show(this, "Set an unlock combo first.", Names.App);
                return false;
            }
            cfg.Chord = chord;
            cfg.LockChord = lockChord;
            cfg.ComboWindowMs = (int)comboWindow.Value;
            cfg.IdleSeconds = (int)idle.Value;
            if (cfg.IdleSeconds > 0 && cfg.IdleSeconds < 10) cfg.IdleSeconds = 10;
            cfg.StrikeLimit = (int)strikeLimit.Value;
            cfg.StrikeWindowSeconds = (int)strikeWindow.Value;
            cfg.TestSeconds = (int)testSeconds.Value;
            cfg.AfterWindowsUnlock = afterUnlock.SelectedIndex < 0 ? 1 : afterUnlock.SelectedIndex;
            cfg.FreezeOnStart = freezeOnStart.Checked;
            cfg.PhantomMouse = phantom.Checked;
            cfg.Debug = debug.Checked;
            string err = cfg.Save();
            if (err != null)
            {
                MessageBox.Show(this, "Couldn't save: " + err, Names.App);
                return false;
            }
            return true;
        }

        void OnSave(object sender, EventArgs e)
        {
            if (SaveSettings()) MessageBox.Show(this, "Saved.", Names.App);
        }

        void OnInstall(object sender, EventArgs e)
        {
            if (!SaveSettings()) return;
            Cursor = Cursors.WaitCursor;
            string err = Setup.Install();
            Cursor = Cursors.Default;
            UpdateStatus();
            if (err != null) MessageBox.Show(this, "Install failed: " + err, Names.App);
            else MessageBox.Show(this, "Installed. It starts every time you sign in.\n\nUse Test to try it, or Start now to run it without signing out.", Names.App);
        }

        void OnStart(object sender, EventArgs e)
        {
            if (!Setup.IsInstalled())
            {
                MessageBox.Show(this, "Install it first.", Names.App);
                return;
            }
            if (!SaveSettings()) return;
            string msg = freezeOnStart.Checked
                ? "It will freeze straight away. Unlock with: " + Config.Describe(chord) + "\n\nStart now?"
                : "Start now?";
            if (MessageBox.Show(this, msg, Names.App, MessageBoxButtons.OKCancel) != DialogResult.OK) return;
            Setup.StartNow();
            Thread.Sleep(1500);
            UpdateStatus();
        }

        void OnTest(object sender, EventArgs e)
        {
            if (!Setup.IsInstalled())
            {
                MessageBox.Show(this, "Install it first.", Names.App);
                return;
            }
            if (!SaveSettings()) return;
            string msg = "Freezes now and unlocks itself after " + testSeconds.Value + " seconds.\nUnlock early with: " + Config.Describe(chord) + "\n\nStart the test?";
            if (MessageBox.Show(this, msg, Names.App, MessageBoxButtons.OKCancel) != DialogResult.OK) return;
            try { Process.Start(Config.InstalledExe, "--test"); }
            catch (Exception ex) { MessageBox.Show(this, "Couldn't start the test: " + ex.Message, Names.App); }
        }

        void OnUninstall(object sender, EventArgs e)
        {
            if (MessageBox.Show(this, "Remove freezeMe-Security, its settings and its sign-in task?", Names.App, MessageBoxButtons.OKCancel) != DialogResult.OK) return;
            bool closeNow = Setup.Uninstall();
            if (closeNow)
            {
                Close();
                return;
            }
            UpdateStatus();
            MessageBox.Show(this, "Removed.", Names.App);
        }
    }
}
