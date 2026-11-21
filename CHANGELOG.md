# Changelog

## 1.3.0 - 21st of November 2026

Added
- Option to store the unlock combo as a salted hash (PBKDF2), so it can't be read out of freeze.ini.
- Warning when picking "Unfreeze" after unlocking Windows, since that lets in anyone who knows your password.

Fixed
- The debug log no longer writes the combo's own keys. With a hashed combo it doesn't write key names at all.

## 1.2.1 - 21st of November 2026

Fixed
- Double-clicking the exe did nothing. It runs hidden, and with no combo set it just closed. Double-clicking now opens the settings window.
- Icon saved in a format the built-in Windows compiler can read.

Added
- Install / update, Start now, Test and Uninstall buttons in the settings window, plus a status line. The exe can install itself, no setup file needed.

Changed
- Settings are always read from C:\Program Files\freezeMe-Security, wherever the exe is run from.
- The sign-in task starts it with --autostart. Run the install again after updating so the task gets this.
- Start menu shortcut is now just "freezeMe-Security".

## 1.2 - 20th of November 2026

Fixed
- Freezing could stop working completely after signing in, a UAC prompt or Ctrl+Alt+Del. The Windows lock check was reading the wrong value, so it thought Windows was locked and let everything through. It also stopped the Ctrl+Alt+Del lock from firing.
- That check now needs two readings in a row and can't count Windows as locked while the normal desktop is showing.

Added
- Proper installer (freezeMe-Security-Setup.exe) made with Inno Setup. Shows up in Apps & Features, uninstalls cleanly, supports silent install with a preset freeze.ini.
- Icon and version info on the exe.
- GitHub Actions build that attaches the exe, the installer and SHA256 hashes to each release.

Removed
- install.bat, install.ps1 and uninstall.bat. The installer replaces them.

## 1.1 - 20th of November 2026

Added
- Settings window (Start menu > freezeMe-Security Settings, or `--settings`). Changes apply within a couple of seconds, no restart needed.
- Lock key: optional combo (e.g. Ctrl + #) that freezes straight away. It gets swallowed so nothing else sees it.
- Combo window: all unlock keys have to be pressed within 1 second (can be changed).
- Phantom mouse: cursor still moves while frozen, clicks and scrolling do nothing.
- Choice of what happens after you unlock Windows: leave it, freeze, or unfreeze (password is enough).
- Wrong-press limit and the time it's counted over can be changed.
- Debug log (off by default), saved to an admin-only logs folder.
- FUTURE.md with planned features.

Fixed
- Unlock combo sometimes not working until you waited a few seconds. A stray or stuck key now drops out after the combo window, and letting go of a stray key can complete the combo.
- Lock screen being slow or unresponsive. It no longer touches input while Windows is locked, and only locks Windows once per trigger instead of repeating.
- Missed lock/unlock messages from Windows are now picked up by checking the session state every second.

Changed
- Renamed from Freeze to freezeMe-Security. install.bat removes the old Freeze install and keeps its combo.
- install.bat keeps your existing combo and settings when updating.
- Settings file has new options. Old FreezeOnUnlock is still read and converted.

## 1.0 - 20th of November 2026

- First version. Keyboard and mouse lock with a key + mouse button unlock combo, freeze on sign-in and after 5 min idle, Ctrl+Alt+Del and wrong-press Windows lock, watchdog, safe mode recovery.
