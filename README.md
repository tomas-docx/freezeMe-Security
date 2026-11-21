# freezeMe-Security

Download: grab freezeMe-Security-Setup.exe from the latest release (Releases on the right), run it, set your combo. The Code button is only needed if you want to build it yourself.

Locks keyboard and mouse on Windows 10/11 until you press your combo (some keys + a mouse button, all within 1 second, e.g. Ctrl + Win + H + middle click). The screen stays as it is.

It freezes when you sign in, after 5 min idle, after you unlock Windows, or when you press your lock key (optional, e.g. Ctrl + #). Plugging in another keyboard or mouse doesn't get around it, and software input (macros, remote tools) is ignored. Ctrl+Alt+Del can't be blocked by any program, so it locks Windows instead. Same if someone mashes keys (10 wrong presses in 60s by default) or kills the process.

Phantom mouse (optional): the cursor still moves while frozen but clicks and scrolling do nothing.

Install: download `freezeMe-Security-Setup-x.y.z.exe` from Releases and run it. It asks for your combo at the end. Uninstall from Apps & Features like anything else.

Or just the exe: double-click `freezeMe-Security.exe`, set your combo, press Install. The same window has Start now, Test and Uninstall.

Settings: Start menu > freezeMe-Security (or double-click the exe). Changes apply within a couple of seconds. You can change the unlock combo, set or clear the lock key, the combo window, the idle time, the wrong-press limit and how long it's counted over, what happens after you unlock Windows (leave it, freeze, or unfreeze since the password is enough), phantom mouse, and a debug log.

Test mode: press Test in the settings window. It freezes and unlocks itself after 60s.

Silent install (for IT): `freezeMe-Security-Setup-x.y.z.exe /VERYSILENT`. Put a `freeze.ini` next to the setup exe to preset the combo and settings. Without one it installs but won't freeze until a combo is set.

Settings file is `C:\Program Files\freezeMe-Security\freeze.ini` (admin only):

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

Forgot the combo? It doesn't run in Safe Mode. At the sign-in screen hold Shift and click Power > Restart, then Troubleshoot > Advanced options > Startup Settings > Restart, press 4. Sign in, delete `C:\Program Files\freezeMe-Security\freeze.ini`, restart normally and run the setup again.

Doesn't stop Win+L or Ctrl+Alt+Del (both just lock Windows) or the power button. Touchscreens/pens might get through. With phantom mouse on, hovering can still show tooltips and the like.

Building it yourself: `build.bat` makes the exe (uses the csc.exe that comes with Windows), then compile `installer.iss` with Inno Setup 6 to get the setup in `dist\`. Pushing a `v*` tag makes GitHub Actions build both and attach them to a release with SHA256 hashes.

Code is all in `freezeMe-Security.cs`, sections are numbered `// 1.` to `// 11.`. Has to stay C# 5 because the built-in csc.exe is old. To release: Releases > Draft a new release > new tag like v1.2.2 > Publish. The build takes the version from the tag. Don't commit `freeze.ini`, it has your combo. Plans are in `FUTURE.md`, changes in `CHANGELOG.md`.

(C) tomas-docx 2026. MIT licence, use it however you want but keep the copyright notice.
