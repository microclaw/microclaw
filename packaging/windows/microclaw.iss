#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif

#ifndef SourceDir
  #define SourceDir "..\\..\\target\\windows-installer\\app"
#endif

#ifndef OutputDir
  #define OutputDir "..\\..\\target\\windows-installer\\out"
#endif

#ifndef OutputBaseFilename
  #define OutputBaseFilename "microclaw-" + AppVersion + "-windows-setup"
#endif

#ifndef ArchitecturesAllowed
  #define ArchitecturesAllowed "x64compatible"
#endif

#ifndef ArchitecturesInstallIn64BitMode
  #define ArchitecturesInstallIn64BitMode "x64compatible"
#endif

[Setup]
AppId={{D22D53B8-392D-4F35-A3A7-8D1B4EB2F4C9}
AppName=MicroClaw
AppVersion={#AppVersion}
AppVerName=MicroClaw {#AppVersion}
AppPublisher=MicroClaw
AppPublisherURL=https://microclaw.ai
AppSupportURL=https://github.com/microclaw/microclaw
AppUpdatesURL=https://github.com/microclaw/microclaw/releases
VersionInfoVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\MicroClaw
DefaultGroupName=MicroClaw
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
SetupIconFile=..\..\web\dist\favicon.ico
UninstallDisplayIcon={app}\microclaw.exe
PrivilegesRequired=lowest
ArchitecturesAllowed={#ArchitecturesAllowed}
ArchitecturesInstallIn64BitMode={#ArchitecturesInstallIn64BitMode}
ChangesEnvironment=yes
Compression=lzma2/max
SolidCompression=yes
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseFilename}
WizardStyle=modern

[Tasks]
Name: addtopath; Description: "Add MicroClaw to your user PATH"; Flags: checkedonce

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\MicroClaw"; Filename: "{app}\microclaw.exe"; WorkingDir: "{app}"
Name: "{group}\MicroClaw Setup"; Filename: "{app}\microclaw.exe"; Parameters: "setup"; WorkingDir: "{app}"
Name: "{group}\MicroClaw Doctor"; Filename: "{app}\microclaw.exe"; Parameters: "doctor"; WorkingDir: "{app}"
Name: "{group}\Uninstall MicroClaw"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\microclaw.exe"; Parameters: "setup"; Description: "Run microclaw setup"; Flags: nowait postinstall skipifsilent unchecked

[Code]
const
  EnvironmentKey = 'Environment';
  PathValueName = 'Path';
  MC_HWND_BROADCAST = $FFFF;
  MC_WM_SETTINGCHANGE = $001A;
  MC_SMTO_ABORTIFHUNG = $0002;

function SendMessageTimeout(
  hWnd: Integer;
  Msg: Integer;
  wParam: Integer;
  lParam: String;
  fuFlags: Integer;
  uTimeout: Integer;
  var lpdwResult: Integer
): Integer;
  external 'SendMessageTimeoutW@user32.dll stdcall';

function NormalizePath(const Value: string): string;
begin
  Result := Lowercase(RemoveBackslashUnlessRoot(Trim(Value)));
end;

function SplitNextPathSegment(var Value: string): string;
var
  DelimiterPos: Integer;
begin
  DelimiterPos := Pos(';', Value);
  if DelimiterPos = 0 then
  begin
    Result := Trim(Value);
    Value := '';
  end
  else
  begin
    Result := Trim(Copy(Value, 1, DelimiterPos - 1));
    Delete(Value, 1, DelimiterPos);
  end;
end;

function PathContainsDir(const PathValue: string; const Dir: string): Boolean;
var
  Remaining: string;
  Segment: string;
begin
  Remaining := PathValue;
  while Remaining <> '' do
  begin
    Segment := SplitNextPathSegment(Remaining);
    if (Segment <> '') and (NormalizePath(Segment) = NormalizePath(Dir)) then
    begin
      Result := True;
      exit;
    end;
  end;

  Result := False;
end;

function RemoveDirFromPathValue(const PathValue: string; const Dir: string): string;
var
  Remaining: string;
  Segment: string;
  NewValue: string;
begin
  Remaining := PathValue;
  NewValue := '';
  while Remaining <> '' do
  begin
    Segment := SplitNextPathSegment(Remaining);
    if (Segment <> '') and (NormalizePath(Segment) <> NormalizePath(Dir)) then
    begin
      if NewValue = '' then
        NewValue := Segment
      else
        NewValue := NewValue + ';' + Segment;
    end;
  end;

  Result := NewValue;
end;

procedure BroadcastEnvironmentChange;
var
  ResultCode: Integer;
begin
  SendMessageTimeout(
    MC_HWND_BROADCAST,
    MC_WM_SETTINGCHANGE,
    0,
    'Environment',
    MC_SMTO_ABORTIFHUNG,
    5000,
    ResultCode
  );
end;

procedure AddInstallDirToUserPath;
var
  CurrentPath: string;
  UpdatedPath: string;
  InstallDir: string;
begin
  InstallDir := ExpandConstant('{app}');
  if not RegQueryStringValue(HKCU, EnvironmentKey, PathValueName, CurrentPath) then
    CurrentPath := '';

  if PathContainsDir(CurrentPath, InstallDir) then
    exit;

  if CurrentPath = '' then
    UpdatedPath := InstallDir
  else
    UpdatedPath := CurrentPath + ';' + InstallDir;

  if RegWriteExpandStringValue(HKCU, EnvironmentKey, PathValueName, UpdatedPath) then
    BroadcastEnvironmentChange
  else
    SuppressibleMsgBox(
      'MicroClaw was installed, but the installer could not add it to your user PATH.',
      mbCriticalError,
      MB_OK,
      IDOK
    );
end;

procedure RemoveInstallDirFromUserPath;
var
  CurrentPath: string;
  UpdatedPath: string;
  InstallDir: string;
begin
  InstallDir := ExpandConstant('{app}');
  if not RegQueryStringValue(HKCU, EnvironmentKey, PathValueName, CurrentPath) then
    exit;

  UpdatedPath := RemoveDirFromPathValue(CurrentPath, InstallDir);
  if UpdatedPath = CurrentPath then
    exit;

  if UpdatedPath = '' then
  begin
    if RegDeleteValue(HKCU, EnvironmentKey, PathValueName) then
      BroadcastEnvironmentChange;
  end
  else if RegWriteExpandStringValue(HKCU, EnvironmentKey, PathValueName, UpdatedPath) then
    BroadcastEnvironmentChange;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    AddInstallDirToUserPath;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveInstallDirFromUserPath;
end;
