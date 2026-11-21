; freezeMe-Security installer (Inno Setup 6)
; (C) tomas-docx 2026
;
; Build: run build.bat first, then compile this with Inno Setup (ISCC.exe installer.iss).
; Output goes to dist\. GitHub Actions does both, see .github\workflows\build.yml
;
; Silent install for IT: freezeMe-Security-Setup-x.y.z.exe /VERYSILENT
; Put a freeze.ini next to the setup exe to preset the combo and settings.

#define AppName "freezeMe-Security"
#ifndef AppVersion
  #define AppVersion "1.2.1"
#endif
#define AppPublisher "tomas-docx"
#define AppExe "freezeMe-Security.exe"
#define AppUrl "https://github.com/tomas-docx/freezeMe-Security"

[Setup]
AppId={{23EA8515-1782-456A-A968-206005FEF024}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}
AppUpdatesURL={#AppUrl}/releases
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} installer
VersionInfoCopyright=(C) {#AppPublisher} 2026
DefaultDirName={autopf}\{#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile=LICENSE
SetupIconFile=app.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
OutputDir=dist
OutputBaseFilename={#AppName}-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no

[Files]
Source: "{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion
; optional preset settings next to the setup exe (for IT / silent installs)
Source: "{src}\freeze.ini"; DestDir: "{app}"; Flags: external skipifsourcedoesntexist onlyifdoesntexist

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Parameters: "--settings"

[Run]
; asks for the combo on first install, registers the sign-in task, locks down the files
Filename: "{app}\{#AppExe}"; Parameters: "--setup {code:SilentArg}"; StatusMsg: "Setting up..."; Flags: waituntilterminated
Filename: "{sys}\schtasks.exe"; Parameters: "/run /tn ""{#AppName}"""; Description: "Start it now (freezes straight away, unlock with your combo)"; Flags: postinstall runhidden skipifsilent unchecked

[UninstallDelete]
Type: files; Name: "{app}\freeze.ini"
Type: files; Name: "{app}\freeze.state"
Type: filesandordirs; Name: "{app}\logs"

[Code]
function SilentArg(Param: String): String;
begin
  if WizardSilent then
    Result := '--silent'
  else
    Result := '';
end;

procedure StopApp(RemoveTask: Boolean);
var
  ResultCode: Integer;
  Exe: String;
begin
  Exe := ExpandConstant('{app}\{#AppExe}');
  if FileExists(Exe) then
  begin
    Exec(Exe, '--stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(2500);
    if RemoveTask then
      Exec(Exe, '--remove-task', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

// stop a running copy before updating it
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopApp(False);
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    StopApp(True);
end;
