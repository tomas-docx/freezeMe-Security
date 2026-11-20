# freezeMe-Security

Locks keyboard and mouse on Windows 10/11 until you hold your combo (some keys + a mouse button at the same time, e.g. Ctrl + Win + H + middle click). Screen stays as it is, cursor doesn't move.

It freezes when you sign in, after 5 min idle, and after you unlock Windows. Plugging in another keyboard or mouse doesn't get around it, and software input (macros, remote tools) is ignored. Ctrl+Alt+Del can't be blocked by any program, so it locks Windows instead. Same if someone mashes keys (10 wrong presses in 60s) or kills the process.

Install:

1. run `build.bat`
2. run `install.bat` as admin, enter your combo twice
3. test it from an admin terminal, it unlocks itself after 60s:

```
"C:\Program Files\freezeMe-Security\freezeMe-Security.exe" --test
```

After that it starts every time you sign in. To start it now:

```
schtasks /run /tn freezeMe-Security
```

Other commands (admin): `--enrol` changes the combo, `--stop` stops it. `uninstall.bat` removes it.

Settings are in `C:\Program Files\freezeMe-Security\freeze.ini` (admin only):

```
Chord=K72,K91,K162,M3     K = virtual-key code, M1-M5 = left/right/middle/back/forward
IdleSeconds=300           0 = off
FreezeOnStart=1
FreezeOnUnlock=1
StrikeLimit=10            0 = off
StrikeWindowSeconds=60
TestSeconds=60
```

Forgot the combo? It doesn't run in Safe Mode. Boot into Safe Mode, delete `freeze.ini`, restart and run `install.bat` again.

Doesn't stop Win+L or Ctrl+Alt+Del (both just lock Windows) or the power button. Touchscreens/pens might get through.

Code is all in `freezeMe-Security.cs`, sections are numbered `// 1.` to `// 9.`. Edit, `build.bat`, `install.bat` again (keeps your combo), test with `--test`. Has to stay C# 5 because the csc.exe built into Windows is old. Don't commit `freeze.ini`, it has your combo.

(C) tomas-docx 2026. MIT licence, use it however you want but keep the copyright notice.
