#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif

#ifndef SourceDir
  #define SourceDir "..\\..\\..\\target\\microclaw-desktop-windows-installer\\app"
#endif

#ifndef OutputDir
  #define OutputDir "..\\..\\..\\target\\microclaw-desktop-windows-installer\\out"
#endif

#ifndef OutputBaseFilename
  #define OutputBaseFilename "MicroClaw-Desktop-" + AppVersion + "-windows-setup"
#endif

#ifndef IconFile
  #define IconFile "MicroClawDesktop.ico"
#endif

#ifndef ArchitecturesAllowed
  #define ArchitecturesAllowed "x64compatible"
#endif

#ifndef ArchitecturesInstallIn64BitMode
  #define ArchitecturesInstallIn64BitMode "x64compatible"
#endif

[Setup]
AppId={{A3FD7C64-CF87-469B-AF60-ED428BA21393}
AppName=MicroClaw Desktop
AppVersion={#AppVersion}
AppVerName=MicroClaw Desktop {#AppVersion}
AppPublisher=MicroClaw
AppPublisherURL=https://microclaw.org
AppSupportURL=https://github.com/microclaw/microclaw/issues
AppUpdatesURL=https://github.com/microclaw/microclaw/releases
VersionInfoVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\MicroClaw Desktop
DefaultGroupName=MicroClaw Desktop
DisableProgramGroupPage=yes
LicenseFile={#SourceDir}\LICENSE.txt
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\microclaw-desktop.exe
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
Name: "{group}\MicroClaw Desktop"; Filename: "{app}\microclaw-desktop.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\MicroClaw Desktop"; Filename: "{app}\microclaw-desktop.exe"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{group}\Uninstall MicroClaw Desktop"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\microclaw-desktop.exe"; Description: "Launch MicroClaw Desktop"; Flags: nowait postinstall skipifsilent
