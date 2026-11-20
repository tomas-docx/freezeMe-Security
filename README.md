# freezeMe-Security

Locks keyboard and mouse on Windows 10/11 until you press your combo (some keys + a mouse button, all within 1 second, e.g. Ctrl + Win + H + middle click). The screen stays as it is.

It freezes when you sign in, after 5 min idle, after you unlock Windows, or when you press your lock key (optional, e.g. Ctrl + #). Plugging in another keyboard or mouse doesn't get around it, and software input (macros, remote tools) is ignored. Ctrl+Alt+Del can't be blocked by any program, so it locks Windows instead. Same if someone mashes keys (10 wrong presses in 60s by default) or kills the process.

Phantom mouse (optional): the cursor still moves while frozen but clicks and scrolling do nothing.

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

Settings: Start menu > freezeMe-Security Settings (or run the exe with `--settings`). Changes apply within a couple of seconds, no restart. You can change the unlock combo, set or clear the lock key, the combo window, the idle time, the wrong-press limit and how long it's counted over, what happens after you unlock Windows (stay frozen, freeze, or unfreeze since the password is enough), phantom mouse, and a debug log.

It's all stored in `C:\Program Files\freezeMe-Security\freeze.ini` (admin only) if you'd rather edit it by hand:

```
Chord=K72,K91,K162,M3     K = virtual-key code, M1-M5 = left/right/middle/back/forward
LockKey=K162,K222         blank = off
ComboWindowMs=1000
IdleSeconds=300           0 = off
StrikeLimit=10            0 = off
StrikeWindowSeconds=60
PhantomMouse=0
FreezeOnStart=1
AfterWindowsUnlock=1      0 leave as it was, 1 freeze, 2 unfreeze
TestSeconds=60
Debug=0
```

Other commands (admin): `--stop` stops it. `uninstall.bat` removes it.

Forgot the combo? It doesn't run in Safe Mode. At the sign-in screen hold Shift and click Power > Restart, then Troubleshoot > Advanced options > Startup Settings > Restart, press 4. Sign in, delete `C:\Program Files\freezeMe-Security\freeze.ini`, restart normally and run `install.bat` again.

Doesn't stop Win+L or Ctrl+Alt+Del (both just lock Windows) or the power button. Touchscreens/pens might get through. With phantom mouse on, hovering can still show tooltips and the like.

Code is all in `freezeMe-Security.cs`, sections are numbered `// 1.` to `// 11.`. Edit, `build.bat`, `install.bat` again (keeps your settings), test with `--test`. Has to stay C# 5 because the csc.exe built into Windows is old. Don't commit `freeze.ini`, it has your combo. Plans are in `FUTURE.md`.

(C) tomas-docx 2026. MIT licence, use it however you want but keep the copyright notice.
