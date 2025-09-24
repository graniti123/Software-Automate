<# 
Projekt: Hybrid-Software-Installation
Autor: Granit Elshani
Beschreibung: 
Automatisierte Installation von Standard- und Spezialsoftware auf einem Windows-Rechner.
Alle Installationen erfolgen im Silent-Mode.
Logs werden zentral dokumentiert: \\YourServer\programme\Software\logs_Powershell
#>

$LogPath = "\\server\logs\Büro-Software-Install.log"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMsg = "$time [$Level] $Message"
    Add-Content -Path $LogPath -Value $logMsg
    Write-Host $Message
}

################################################################################################################################
# -----------------------------
# CHOCOLATEY
# -----------------------------
################################################################################################################################

function Ensure-Chocolatey {
    if (!(Get-Command choco.exe -ErrorAction SilentlyContinue)) {
        Write-Log "Chocolatey nicht gefunden. Installiere Chocolatey..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Log "Chocolatey erfolgreich installiert." "SUCCESS"
    } else {
        Write-Log "Chocolatey bereits vorhanden." "SUCCESS"
    }
}

function Install-ChocoApps {
    param([string[]]$Apps)

    foreach ($app in $Apps) {
        # Prüfen ob App schon installiert
        $installed = choco list --local-only | Select-String -Pattern "^$app"
        if ($installed) {
            Write-Log "$app ist bereits installiert. Überspringe Installation." "INFO"
            continue
        }

        Write-Log "Starte Installation für $app..."
        try {
            choco install $app -y --ignore-checksums --no-progress
            Write-Log "$app erfolgreich installiert." "SUCCESS"
        } catch {
            Write-Log ("Fehler bei Installation von {0}: {1}" -f $app, $_) "ERROR"
        }
    }
    Write-Log "Alle Choco-Apps wurden installiert oder übersprungen." "SUCCESS"
}

################################################################################################################################
# -----------------------------
# OFFICE 2019
# -----------------------------
################################################################################################################################

function Install-Office2019 {
    param([string]$SourceFolder)
    $TempFolder = "C:\Temp\Office_2019"
    if (!(Test-Path $TempFolder)) { New-Item -Path $TempFolder -ItemType Directory -Force | Out-Null }
    $SetupExe = Join-Path $TempFolder "setup.exe"
    $XmlFile = Join-Path $TempFolder "configuration.xml"
    $OutFile = Join-Path $TempFolder "office_out.txt"
    $ErrFile = Join-Path $TempFolder "office_err.txt"

    if (!(Test-Path $SourceFolder)) {
        Write-Log "Office 2019 Quellordner nicht gefunden: $SourceFolder" "ERROR"
        return
    }

    Write-Log "Kopiere Office 2019 Setup..."
    Copy-Item -Path $SourceFolder -Destination $TempFolder -Recurse -Force
    Write-Log "Office Setup kopiert." "SUCCESS"

    if ((Test-Path $SetupExe) -and (Test-Path $XmlFile)) {
        Write-Log "Starte Office 2019 Installation..."
        Start-Process -FilePath $SetupExe -ArgumentList "/configure `"$XmlFile`"" -Wait -RedirectStandardOutput $OutFile -RedirectStandardError $ErrFile
        Write-Log "Office 2019 Installation abgeschlossen." "SUCCESS"
    } else {
        Write-Log "Setup oder XML nicht gefunden im Temp-Ordner!" "ERROR"
    }

    if (Test-Path $TempFolder) {
        Remove-Item $TempFolder -Recurse -Force
        Write-Log "Temporärer Office Ordner gelöscht."
    }
}

################################################################################################################################
# -----------------------------
# MYAPPS
# -----------------------------
################################################################################################################################

function Run-PowerShellScript {
    param([string]$ScriptPath, [string]$Name)
    if (Test-Path $ScriptPath) {
        Write-Log "Starte $Name Script..."
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy RemoteSigned -File `"$ScriptPath`"" -Wait
            Write-Log "$Name erfolgreich installiert." "SUCCESS"
        } catch {
            Write-Log ("Fehler bei {0}: {1}" -f $Name, $_) "ERROR"
        }
    } else {
        Write-Log "$Name Script nicht gefunden: $ScriptPath" "WARNING"
    }
}

################################################################################################################################
# -----------------------------
# EVA STARTER
# -----------------------------
################################################################################################################################

function Copy-FileToPublicDesktop {
    param([string]$SourceFile, [string]$Name)
    if (Test-Path $SourceFile) {
        $destination = Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) (Split-Path $SourceFile -Leaf)
        Copy-Item $SourceFile $destination -Force
        Write-Log "$Name auf öffentlichem Desktop erstellt." "SUCCESS"
    } else {
        Write-Log "$Name Datei nicht gefunden: $SourceFile" "WARNING"
    }
}

################################################################################################################################
# -----------------------------
# CITRIX WORKSPACE
# -----------------------------
################################################################################################################################
function Install-CitrixWorkspace {
    param([string]$SourceExe)

    # Pfad zur installierten Citrix Workspace App
    $CitrixExe = "$env:ProgramFiles\Citrix\ICA Client\SelfServicePlugin\SelfService.exe"

    if (Test-Path $CitrixExe) {
        Write-Log "Citrix Workspace bereits installiert. Überspringe Installation." "INFO"
        return
    }

    if (Test-Path $SourceExe) {
        $Temp = "C:\Temp\CitrixWorkspace.exe"
        Copy-Item $SourceExe $Temp -Force
        Write-Log "Starte Citrix Workspace Installation..."

        # Silent-Installation ohne auf Prozess zu warten
        $arguments = "/silent /AutoUpdateCheck=disabled /noreboot DONOTSTARTCC=1"
        Start-Process -FilePath $Temp -ArgumentList $arguments -WindowStyle Hidden
        Write-Log "Citrix Workspace Installer gestartet. Installation läuft im Hintergrund." "INFO"

        # Kurze Pause, um sicherzustellen, dass der Installer gestartet wurde
        Start-Sleep -Seconds 10
    } else {
        Write-Log "Citrix Workspace Setup nicht gefunden: $SourceExe" "WARNING"
    }
}
################################################################################################################################
# -----------------------------
# WINDREAM CLIENT
# -----------------------------
################################################################################################################################

function Install-WindreamClient {
    param(
        [string]$Source = "\\server\Windream_Client\",
        [string]$Destination = "C:\Temp\Windream_Client\"
    )

    Write-Log "Starte Windream Client Installation..."

    if (!(Test-Path $Source)) {
        Write-Log "Quellverzeichnis nicht gefunden: $Source" "ERROR"
        return
    }

    if (Test-Path $Destination) { Remove-Item -Path $Destination -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null

    try {
        Copy-Item -Path "$Source\*" -Destination $Destination -Recurse -Force
        Write-Log "Windream Dateien erfolgreich kopiert." "SUCCESS"
    } catch {
        Write-Log "Fehler beim Kopieren der Dateien: $_" "ERROR"
        return
    }

    # MSI Installation
    $MsiFile = Get-ChildItem $Destination -Filter "*.msi" | Select-Object -First 1
    $TransformFile = Join-Path $Destination "1031.mst"

    if ($MsiFile) {
        $msiArgs = "/i `"$($MsiFile.FullName)`" /qn TRANSFORMS=`"$TransformFile`" WMVAR_SETTING_AUTOREBOOT=0 WMVAR_SETTING_SERVERNAME=Server WMVAR_SETTING_INSTLANGUAGE=0007 WMVAR_SETTING_PORT=53465 WMVAR_SETTING_DRIVERTYPE=0 WMVAR_RUN_SCRIPT=`"$Destination\PostSetup\PatchDefault.vbs`" WMVAR_RUN_SCRIPT_EXITONFAIL=1"
        Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait
        Write-Log "Windream MSI Installation abgeschlossen." "SUCCESS"
    } else {
        Write-Log "Windream MSI-Datei nicht gefunden!" "ERROR"
        return
    }

    # Shortcut im globalen Startup-Ordner (nur kopieren, nicht starten)
    $WindreamExe = "$env:ProgramFiles\windream GmbH\windream\wmcc.exe"
    $StartupFolder = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    $Shell = New-Object -ComObject WScript.Shell

    if (Test-Path $WindreamExe) {
        $shortcut = $Shell.CreateShortcut("$StartupFolder\wmcc.lnk")
        $shortcut.TargetPath = $WindreamExe
        $shortcut.WorkingDirectory = Split-Path $WindreamExe
        $shortcut.IconLocation = $WindreamExe
        $shortcut.Save()
        Write-Log "Windream Client Shortcut im Startup-Ordner erstellt (wird nicht gestartet)." "SUCCESS"
    } else {
        Write-Log "Windream Executable nicht gefunden: $WindreamExe" "WARNING"
    }   
}
################################################################################################################################
# -----------------------------
# START INSTALLATION
# -----------------------------
################################################################################################################################
Write-Log ">>> Starte Softwareinstallation <<<"

# Aufruf
Ensure-Chocolatey
# Firefox: Sicherer Browser für den täglichen Gebrauch, mit Fokus auf Privatsphäre.
# Notepad++: Erweiterter Texteditor mit Syntax-Highlighting für Coding und Notizen.
# Java Runtime: Ermöglicht Ausführung von Java-Anwendungen, notwendig für plattformübergreifende Tools.
# Greenshot: Einfaches Tool zum Erstellen und Bearbeiten von Screenshots.
# 7-Zip: Effizientes Tool zur Dateikomprimierung und -Extraktion.
$ChocoApps = @("firefox","notepadplusplus.install","javaruntime","greenshot","7zip")
Install-ChocoApps -Apps $ChocoApps


# Office 2019: Produktivitätssuite für Dokumente, Tabellen und E-Mails.
$OfficeSource = "\\server\Office_2019\"
$officeInstalled = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object { $_.DisplayName -like "*Office*" }
if (-not $officeInstalled) {
    Install-Office2019 -SourceFolder $OfficeSource
} else {
    Write-Log "Office bereits installiert. Überspringe Installation." "INFO"
}

# Office Shortcuts
$apps = @{
    "Word"    = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    "Excel"   = "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
    "Outlook" = "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
}
$PublicDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
$Shell = New-Object -ComObject WScript.Shell
foreach ($name in $apps.Keys) {
    $exe = $apps[$name]
    if (Test-Path $exe) {
        $shortcut = $Shell.CreateShortcut("$PublicDesktop\$name.lnk")
        $shortcut.TargetPath = $exe
        $shortcut.Save()
        Write-Log "$name Shortcut erstellt auf öffentlichem Desktop." "SUCCESS"
    }
}

# MyApps: Custom-Script zur App-Verwaltung und -Bereitstellung.
$MyAppsScript = "\\server\myapps.ps1"
Run-PowerShellScript -ScriptPath $MyAppsScript -Name "MyApps"

# EVA Starter: Launcher für enterprise-spezifische Anwendungen.
$EvaFile = "\\server\EVA_Start.jnlp"
Copy-FileToPublicDesktop -SourceFile $EvaFile -Name "EVA Starter"

# Citrix Workspace: Tool für Fernzugriff auf Desktops und Apps.
$CitrixExe = "\\server\CitrixWorkspace.exe"
Install-CitrixWorkspace -SourceExe $CitrixExe

################################################################################################################################
# Bitdefender Endpoint Security Tools
################################################################################################################################
# Bitdefender: Endpoint-Sicherheit gegen Malware und Bedrohungen.
$CompanyHash = "ANONYMIZED_HASH"

$Installed = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
Where-Object { $_.DisplayName -eq "Bitdefender Endpoint Security Tools" }

if ($Installed) {
    Write-Output "Bitdefender already installed. Exiting."
} else {
    $BitdefenderURL = "setupdownloader_[$CompanyHash].exe"
    $BaseURL = "https://cloud.gravityzone.bitdefender.com/Packages/BSTWIN/0/"
    $URL = $BaseURL + $BitdefenderURL
    $Destination = 'C:\Temp\setupdownloader.exe'

    try {
        Write-Output "Beginning download of Bitdefender to $Destination"
        Invoke-WebRequest -Uri $URL -OutFile $Destination
    } catch {
        Write-Output "Error Downloading - $_.Exception.Response.StatusCode.value_"
        Write-Output $_
        Exit 1
    }

    $FullDestination = "$DestinationPath\setupdownloader_[$CompanyHash].exe"
    if (Test-Path $FullDestination) {
       Remove-Item $FullDestination
       Write-Output "Removed $FullDestination..."
    }

    Rename-Item -Path $Destination -NewName "setupdownloader_[$CompanyHash].exe"
    Write-Output "Download succeeded, beginning install..."
    Start-Process -FilePath "C:\Temp\$BitdefenderURL" -ArgumentList "/bdparams /silent silent" -Wait -NoNewWindow

    Start-Sleep -Seconds 30

    $Installed = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
    Where-Object { $_.DisplayName -eq "Bitdefender Endpoint Security Tools" }

    if ($Installed) {
        Write-Output "Bitdefender successfully installed."
    } else {
        Write-Output "ERROR: Failed to install Bitdefender"
    }
}
################################################################################################################################
# Windream Client als letzte Software installieren
################################################################################################################################
# Windream Client: DMS-Client für Dokumentenarchivierung und -Suche.
Install-WindreamClient

################################################################################################################################
# TEMP CLEANUP
################################################################################################################################
try {
    if (Test-Path "C:\Temp") {
        Remove-Item -Path "C:\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Alle temporären Dateien in C:\Temp gelöscht." "SUCCESS"
    } else {
        Write-Log "C:\Temp existiert nicht. Kein Cleanup erforderlich." "INFO"
    }
} catch {
    Write-Log "Fehler beim Löschen der temporären Dateien: $_" "WARNING"
}

Write-Log ">>> Alle Installationen abgeschlossen <<<" "SUCCESS"