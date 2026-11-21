# Future plans

Not in the current build.

Next

- Tray icon, on by default, with an option to hide it.
- Debug log: times and counts only by default, key names only in a detailed mode.
- Show the watchdog in settings as "Tamper protection", with an on/off.
- First-run screen that explains what it does.
- When not frozen, swallow the unlock combo too, so it can't set off Windows shortcuts (e.g. Win+H turns on voice typing and asks for the microphone).
- Check each release on VirusTotal and send any false positives to Microsoft.
- Short page for IT: silent install, preset freeze.ini, what it logs, how to remove it.

Ghost mode

- Instead of (or as well as) locking Windows, the PC looks like it works but nothing loads. Apps hang, pages buffer forever, nothing obviously "locked".
- Option to replace the lockout or run alongside it.
- Kicks in after 5 failed attempts instead of 10: 5 ghost clicks, 5 wrong combos, or 5 goes at typing.
- Only triggers on a failed combo or someone using the mouse/keyboard while frozen.
- Needs a subtle sign so the real owner doesn't get caught by it by accident, e.g. the taskbar slowly fading from blue to light blue and back.

Intruder log

- Option to log the time, number of tries, which keys were pressed etc.
- Option to take a silent photo or short video with the webcam (if there is one) when someone moves the mouse, presses keys or tries a wrong combo.

Business / multi-user

- Right now the sign-in task is made for whoever runs the setup. If a standard user installs it with an admin's password, it gets set up for the admin account instead. Needs a per-machine option that runs for every user who signs in.
- Code signing once there's a company to sign under.
