// freezeMe-Security - keyboard + mouse locker for Windows 10/11
// (C) tomas-docx 2026
//
// Unlocks when you hold your combo (keys + mouse buttons together).
// Build with build.bat. Has to stay C# 5 for the csc.exe that comes with Windows.
//
// Usage:
//   freezeMe-Security.exe            normal, started by the scheduled task at sign-in
//   freezeMe-Security.exe --enrol    set the combo (admin)
//   freezeMe-Security.exe --test     freeze, unlock after TestSeconds
//   freezeMe-Security.exe --stop     stop it (admin)
//
// Sections (search "// 1." etc):
//   1 Names  2 Native  3 Hooks  4 Config  5 State
//   6 Program  7 Watchdog  8 LockerForm  9 EnrolForm
//
// Input ids: keys = virtual-key code (1-255), mouse = 1001 left, 1002 right,
// 1003 middle, 1004 back, 1005 forward. In freeze.ini: K72,K91,M3 etc.
//
// OnButton/OnMotion run inside the hook, keep them fast (Windows drops slow hooks).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace FreezeMeSecurity
{
    // 1. Names
    static class Names
    {
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
        public const int WM_MOUSEWHEEL = 0x020A;
        public const int WM_XBUTTONDOWN = 0x020B;
        public const int WM_XBUTTONUP = 0x020C;
        public const int WM_MOUSEHWHEEL = 0x020E;

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
    }

    // 3. Hooks
    static class Hooks
    {
        // return true to swallow
        public static Func<int, bool, bool, bool, bool> OnButton;   // (id, down, up, injected)
        public static Func<bool, bool> OnMotion;                     // (injected) for moves and scrolls
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

        public static bool Installed
        {
            get { return kbHook != IntPtr.Zero && msHook != IntPtr.Zero; }
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
                    else swallow = OnMotion != null && OnMotion(injected);
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
        public HashSet<int> Chord = new HashSet<int>();
        public int IdleSeconds = 300;
        public bool FreezeOnStart = true;
        public bool FreezeOnUnlock = true;
        public int StrikeLimit = 10;
        public int StrikeWindowSeconds = 60;
        public int TestSeconds = 60;

        public static string Dir { get { return Path.GetDirectoryName(Application.ExecutablePath); } }
        public static string IniPath { get { return Path.Combine(Dir, "freeze.ini"); } }
        public static string StatePath { get { return Path.Combine(Dir, "freeze.state"); } }

        public bool IsValid { get { return HasKeyAndMouse(Chord); } }

        public static bool HasKeyAndMouse(IEnumerable<int> set)
        {
            bool key = false, mouse = false;
            foreach (int id in set)
            {
                if (id >= 1000) mouse = true; else key = true;
            }
            return key && mouse;
        }

        public static Config Load()
        {
            Config c = new Config();
            if (!File.Exists(IniPath)) return c;
            string[] lines;
            try { lines = File.ReadAllLines(IniPath); }
            catch { return c; }
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
                    case "idleseconds":
                        c.IdleSeconds = ParseInt(v, c.IdleSeconds, 0, 86400);
                        if (c.IdleSeconds > 0 && c.IdleSeconds < 10) c.IdleSeconds = 10;
                        break;
                    case "freezeonstart": c.FreezeOnStart = ParseBool(v, c.FreezeOnStart); break;
                    case "freezeonunlock": c.FreezeOnUnlock = ParseBool(v, c.FreezeOnUnlock); break;
                    case "strikelimit": c.StrikeLimit = ParseInt(v, c.StrikeLimit, 0, 1000); break;
                    case "strikewindowseconds": c.StrikeWindowSeconds = ParseInt(v, c.StrikeWindowSeconds, 1, 3600); break;
                    case "testseconds": c.TestSeconds = ParseInt(v, c.TestSeconds, 5, 3600); break;
                }
            }
            return c;
        }

        public string Save()
        {
            List<string> parts = new List<string>();
            foreach (int id in Sorted(Chord)) parts.Add(id >= 1000 ? "M" + (id - 1000) : "K" + id);
            string[] lines =
            {
                "; freezeMe-Security settings. Change the combo with: freezeMe-Security.exe --enrol (admin)",
                "Chord=" + string.Join(",", parts.ToArray()),
                "; Seconds of no input before freezing (0 = off)",
                "IdleSeconds=" + IdleSeconds,
                "; Freeze as soon as you sign in (1 = yes, 0 = no)",
                "FreezeOnStart=" + (FreezeOnStart ? 1 : 0),
                "; Freeze again every time you unlock Windows (1 = yes, 0 = no)",
                "FreezeOnUnlock=" + (FreezeOnUnlock ? 1 : 0),
                "; Wrong presses within StrikeWindowSeconds that force a real Windows lock (0 = off)",
                "StrikeLimit=" + StrikeLimit,
                "StrikeWindowSeconds=" + StrikeWindowSeconds,
                "; How long --test mode stays frozen before unlocking itself",
                "TestSeconds=" + TestSeconds
            };
            try
            {
                File.WriteAllLines(IniPath, lines);
                return null;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
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
            return string.Join(" + ", names.ToArray());
        }

        public static string Name(int id)
        {
            switch (id)
            {
                case 1001: return "Left click";
                case 1002: return "Right click";
                case 1003: return "Middle click";
                case 1004: return "Mouse side button (back)";
                case 1005: return "Mouse side button (forward)";
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

    // 6. Program
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

            if (mode == "--enrol" || mode == "--enroll")
            {
                Application.Run(new EnrolForm());
                return 0;
            }

            // safe mode = way out if the combo is forgotten
            if (SystemInformation.BootMode != BootMode.Normal) return 0;

            bool test = mode == "--test";
            Config cfg = Config.Load();
            if (!cfg.IsValid)
            {
                // no combo, no freeze
                if (test) MessageBox.Show("No unlock combo saved yet.\n\nRun freezeMe-Security.exe --enrol as administrator first.", "freezeMe-Security");
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

                bool startFrozen = test || mode == "--start-frozen" || (cfg.FreezeOnStart && mode != "--no-start-freeze");
                Application.Run(new LockerForm(cfg, test, startFrozen, stop));
            }
            return 0;
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
                MessageBox.Show("Run this as administrator to stop it.", "freezeMe-Security");
                return 5;
            }
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

    // 7. Watchdog
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

    // 8. LockerForm
    class LockerForm : Form
    {
        readonly Config cfg;
        readonly bool test;
        readonly bool startFrozen;
        readonly EventWaitHandle stop;
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();

        bool initDone, frozen, sessionLocked, tripArmed, pendingLock, watchdogSeen, closing;
        uint frozenAt, unfrozenAt, lastLockCall, lastButtonEvent, activityFloor, lastWatchdogCheck;

        readonly HashSet<int> held = new HashSet<int>();            // held right now (while frozen)
        readonly HashSet<int> swallowedDowns = new HashSet<int>();  // downs we swallowed
        readonly HashSet<int> swallowUps = new HashSet<int>();      // combo keys still down at unlock
        readonly Queue<uint> strikes = new Queue<uint>();

        public LockerForm(Config cfg, bool test, bool startFrozen, EventWaitHandle stop)
        {
            this.cfg = cfg;
            this.test = test;
            this.startFrozen = startFrozen;
            this.stop = stop;
            ShowInTaskbar = false;
            FormBorderStyle = FormBorderStyle.None;
            timer.Interval = 100;
            timer.Tick += OnTick;
            activityFloor = Native.Now();
            lastWatchdogCheck = Native.Now();
            lastLockCall = unchecked(Native.Now() - 10000u);
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

            if (startFrozen) Freeze();
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
                }
                else if (code == Native.WTS_SESSION_UNLOCK)
                {
                    sessionLocked = false;
                    activityFloor = Native.Now();
                    if (frozen || (cfg.FreezeOnUnlock && !test)) Freeze();
                }
            }
            base.WndProc(ref m);
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
            base.OnFormClosed(e);
        }

        void OnTick(object sender, EventArgs e)
        {
            if (closing) return;

            if (stop != null && stop.WaitOne(0))
            {
                closing = true;
                Close();
                return;
            }

            if (frozen)
            {
                if (test && Native.Since(frozenAt) >= cfg.TestSeconds * 1000)
                {
                    Unfreeze();
                    return;
                }

                if (!sessionLocked)
                {
                    bool normalDesktop = Native.InputDesktopIsDefault();
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
                                pendingLock = true;
                            }
                        }
                    }
                    else if (tripArmed)
                    {
                        // ctrl+alt+del screen while frozen
                        pendingLock = true;
                    }

                    if (pendingLock && Native.Since(lastLockCall) > 500)
                    {
                        lastLockCall = Native.Now();
                        Native.LockWorkStation();
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
                    if (idle >= cfg.IdleSeconds * 1000) Freeze();
                }
            }

            if (!test && Native.Since(lastWatchdogCheck) > 2000)
            {
                lastWatchdogCheck = Native.Now();
                CheckWatchdog();
            }
        }

        void CheckWatchdog()
        {
            if (Program.MutexExists(Names.WatchdogMutex))
            {
                watchdogSeen = true;
                return;
            }
            if (watchdogSeen && frozen) ForceWindowsLock(); // watchdog killed while frozen
            watchdogSeen = false;
            Program.SpawnDetached("--spawn-watchdog " + Program.Pid);
        }

        void Freeze()
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
            if (!test) State.Write(true);
        }

        void Unfreeze()
        {
            frozen = false;
            pendingLock = false;
            Hooks.SwallowOnError = false;
            swallowUps.Clear();
            swallowUps.UnionWith(held);
            held.Clear();
            swallowedDowns.Clear();
            strikes.Clear();
            activityFloor = Native.Now();
            unfrozenAt = Native.Now();
            if (!test) BeginInvoke(new Action(delegate { State.Write(false); })); // not inside the hook
        }

        void ForceWindowsLock()
        {
            if (sessionLocked) return;
            pendingLock = true;
            lastLockCall = Native.Now();
            Native.LockWorkStation();
        }

        void Strike(uint now)
        {
            if (cfg.StrikeLimit <= 0) return;
            strikes.Enqueue(now);
            while (strikes.Count > 0 && unchecked((int)(now - strikes.Peek())) > cfg.StrikeWindowSeconds * 1000) strikes.Dequeue();
            if (strikes.Count >= cfg.StrikeLimit)
            {
                strikes.Clear();
                BeginInvoke(new Action(ForceWindowsLock));
            }
        }

        // hook callback
        bool OnButton(int id, bool down, bool up, bool injected)
        {
            if (!frozen)
            {
                if (up && swallowUps.Remove(id)) return true;
                if (down) swallowUps.Remove(id);
                return false;
            }

            if (injected) return true; // ignore SendInput etc

            uint now = Native.Now();
            if (unchecked((int)(now - lastButtonEvent)) > 10000) held.Clear(); // in case an up got lost
            lastButtonEvent = now;

            if (down)
            {
                bool repeat = held.Contains(id); // autorepeat
                held.Add(id);
                swallowedDowns.Add(id);
                if (!repeat)
                {
                    if (held.SetEquals(cfg.Chord))
                    {
                        Unfreeze();
                        return true;
                    }
                    if (!cfg.Chord.Contains(id)) Strike(now);
                }
                return true;
            }

            if (up)
            {
                held.Remove(id);
                if (swallowedDowns.Remove(id)) return true;
                return false; // pressed before freeze, let it through
            }

            return true;
        }

        bool OnMotion(bool injected)
        {
            return frozen;
        }
    }

    // 9. EnrolForm
    class EnrolForm : Form
    {
        const string Intro =
            "Hold your combo (keys + mouse buttons) then let go.\n\n" +
            "Esc to cancel.";

        readonly Label label = new Label();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly HashSet<int> current = new HashSet<int>();
        readonly HashSet<int> biggest = new HashSet<int>();
        readonly HashSet<int> swallowed = new HashSet<int>();
        HashSet<int> first;
        uint lastInput, finishedAt;
        bool finished;

        public EnrolForm()
        {
            Text = "freezeMe-Security - set your unlock combo";
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
            Hooks.OnMotion = delegate(bool injected) { return false; };
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
                if (Native.Since(finishedAt) > 6000) Close();
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
            if (!Config.HasKeyAndMouse(got))
            {
                label.Text = "Got: " + Config.Describe(got) + "\n\nIt needs at least one KEYBOARD key AND one MOUSE button.\nTry again.";
                return;
            }
            if (first == null)
            {
                first = got;
                label.Text = "Got: " + Config.Describe(got) + "\n\nNow do the same combo again to confirm.";
                return;
            }
            if (!first.SetEquals(got))
            {
                first = null;
                label.Text = "That didn't match the first one. Starting over.\n\n" + Intro;
                return;
            }

            Config cfg = Config.Load();
            cfg.Chord = new HashSet<int>(first);
            string err = cfg.Save();
            if (err != null)
            {
                first = null;
                label.Text = "Couldn't save: " + err + "\n\nRun this as administrator.";
                return;
            }

            finished = true;
            finishedAt = Native.Now();
            label.Text = "Saved. Your unlock combo:\n\n" + Config.Describe(first) + "\n\nThis window closes in a few seconds.";
        }
    }
}
