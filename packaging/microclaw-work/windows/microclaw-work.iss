#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif

#ifndef SourceDir
  #define SourceDir "..\\..\\..\\target\\microclaw-work-windows-installer\\app"
#endif

#ifndef OutputDir
  #define OutputDir "..\\..\\..\\target\\microclaw-work-windows-installer\\out"
#endif

#ifndef OutputBaseFilename
  #define OutputBaseFilename "MicroClaw-Work-" + AppVersion + "-windows-setup"
#endif

#ifndef IconFile
  #define IconFile "MicroClawWork.ico"
#endif

#ifndef ArchitecturesAllowed
  #define ArchitecturesAllowed "x64compatible"
#endif

#ifndef ArchitecturesInstallIn64BitMode
  #define ArchitecturesInstallIn64BitMode "x64compatible"
#endif

[Setup]
AppId={{A3FD7C64-CF87-469B-AF60-ED428BA21393}
AppName=MicroClaw Work
AppVersion={#AppVersion}
AppVerName=MicroClaw Work {#AppVersion}
AppPublisher=MicroClaw
AppPublisherURL=https://microclaw.org
AppSupportURL=https://github.com/microclaw/microclaw/issues
AppUpdatesURL=https://github.com/microclaw/microclaw/releases
VersionInfoVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\MicroClaw Work
DefaultGroupName=MicroClaw Work
DisableProgramGroupPage=yes
LicenseFile={#SourceDir}\LICENSE.txt
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\microclaw-work.exe
PrivilegesRequired=lowest
ArchitecturesAllowed={#ArchitecturesAllowed}
ArchitecturesInstallIn64BitMode={#ArchitecturesInstallIn64BitMode}
Compression=lzma2/max
SolidCompression=yes
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseFilename}
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\MicroClaw Work"; Filename: "{app}\microclaw-work.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\MicroClaw Work"; Filename: "{app}\microclaw-work.exe"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{group}\Uninstall MicroClaw Work"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\microclaw-work.exe"; Description: "Launch MicroClaw Work"; Flags: nowait postinstall skipifsilent
