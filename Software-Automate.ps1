<# 
Projekt: Hybrid-Software-Installation
Autor: [ANONYM]
Beschreibung: 
Automatisierte Installation von Standard- und Spezialsoftware auf einem Windows-Rechner.
Alle Installationen erfolgen im Silent-Mode.
Logs werden zentral dokumentiert: \\SERVER\Share\Logs
#>

$LogPath = "\\SERVER\Share\Logs\Software-Install.log"

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
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Log "Chocolatey nicht gefunden. Installiere Chocolatey..."
        
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

        if (Get-Command choco -ErrorAction SilentlyContinue) {
            Write-Log "Chocolatey erfolgreich installiert." "SUCCESS"
        } else {
            Write-Log "Fehler: Chocolatey konnte nicht installiert werden." "ERROR"
        }
    } else {
        Write-Log "Chocolatey ist bereits vorhanden." "INFO"
    }
}

function Install-ChocoApps {
    param([string[]]$Apps)

    foreach ($app in $Apps) {
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
    $SetupExe = Join-Path $TempFolder "setup.exe"
    $XmlFile = Join-Path $TempFolder "configuration.xml"

    if (!(Test-Path $SourceFolder)) {
        Write-Log "Office 2019 Quellordner nicht gefunden: $SourceFolder" "ERROR"
        return
    }

    Write-Log "Kopiere Office 2019 Setup..."
    Copy-Item -Path $SourceFolder -Destination $TempFolder -Recurse -Force
    Write-Log "Office Setup kopiert." "SUCCESS"

    if ((Test-Path $SetupExe) -and (Test-Path $XmlFile)) {
        Write-Log "Starte Office 2019 Installation..."
        Start-Process -FilePath $SetupExe -ArgumentList "/configure `"$XmlFile`"" -Wait -WindowStyle Hidden
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
    $CitrixExe = "$env:ProgramFiles\Citrix\ICA Client\SelfServicePlugin\SelfService.exe"

    if (Test-Path $CitrixExe) {
        Write-Log "Citrix Workspace bereits installiert. Überspringe Installation." "INFO"
        return
    }

    if (Test-Path $SourceExe) {
        $Temp = "C:\Temp\CitrixWorkspace.exe"
        Copy-Item $SourceExe $Temp -Force
        Write-Log "Starte Citrix Workspace Installation..."
        $arguments = "/silent /AutoUpdateCheck=disabled /noreboot DONOTSTARTCC=1"
        Start-Process -FilePath $Temp -ArgumentList $arguments -WindowStyle Hidden
        Write-Log "Citrix Workspace Installer gestartet. Installation läuft im Hintergrund." "INFO"
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
        [string]$Source = "\\SERVER\Share\Software\Windream_Client\",
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

    $MsiFile = Get-ChildItem $Destination -Filter "*.msi" | Select-Object -First 1
    $TransformFile = Join-Path $Destination "1031.mst"

    if ($MsiFile) {
        $msiArgs = "/i `"$($MsiFile.FullName)`" /qn TRANSFORMS=`"$TransformFile`" WMVAR_SETTING_AUTOREBOOT=0 WMVAR_SETTING_SERVERNAME=WindreamServer WMVAR_SETTING_INSTLANGUAGE=0007 WMVAR_SETTING_PORT=53465 WMVAR_SETTING_DRIVERTYPE=0 WMVAR_RUN_SCRIPT=`"$Destination\PostSetup\PatchDefault.vbs`" WMVAR_RUN_SCRIPT_EXITONFAIL=1"
        Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait
        Write-Log "Windream MSI Installation abgeschlossen." "SUCCESS"
    } else {
        Write-Log "Windream MSI-Datei nicht gefunden!" "ERROR"
        return
    }

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

Ensure-Chocolatey
$ChocoApps = @("firefox","notepadplusplus.install","javaruntime","greenshot","7zip")
Install-ChocoApps -Apps $ChocoApps

$OfficeSource = "\\SERVER\Share\Software\Office_2019\"
$officeInstalled = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object { $_.DisplayName -like "*Office*" }
if (-not $officeInstalled) {
    Install-Office2019 -SourceFolder $OfficeSource
} else {
    Write-Log "Office bereits installiert. Überspringe Installation." "INFO"
}

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

$MyAppsScript = "\\SERVER\Share\Scripts\myapps.ps1"
Run-PowerShellScript -ScriptPath $MyAppsScript -Name "MyApps"

$EvaFile = "\\SERVER\Share\Software\EVA_Starter\EVA_Start.jnlp"
Copy-FileToPublicDesktop -SourceFile $EvaFile -Name "EVA Starter"

$CitrixExe = "\\SERVER\Share\Software\CitrixWorkspace\CitrixWorkspace.exe"
Install-CitrixWorkspace -SourceExe $CitrixExe

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

# SIG # Begin signature block
# MIIlyAYJKoZIhvcNAQcCoIIluTCCJbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAUCwIxyrVN7Pby
# d2xDYPQ31BQiYy/XGX83a/fyl8/sX6CCH/AwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggY2MIIFHqADAgECAhMrAAAAboy39ezpNaOPAAEAAABuMA0G
# CSqGSIb3DQEBCwUAMDsxEzARBgoJkiaJk/IsZAEZFgNMQU4xEzARBgoJkiaJk/Is
# ZAEZFgNBS0cxDzANBgNVBAMTBkFLRy1DQTAeFw0yNTA3MDkxNDQwMjBaFw0zMDA3
# MDkxNDUwMjBaMGoxEzARBgoJkiaJk/IsZAEZFgNMQU4xEzARBgoJkiaJk/IsZAEZ
# FgNBS0cxDzANBgNVBAsTBlRlc3RVTTENMAsGA1UECxMEVXNlcjEeMBwGA1UEAxMV
# RWxzaGFuaS1BZG1pbmlzdHJhdG9yMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEAtyfCAIAKs2N6sqDb5fuAjdRFlQ6a3kMsT57UqzWcfA9HwxSoC9BpFniV
# jUxyX/1iflYHZSeJGspA0Why0uVDLtrJikstkvxSSLDzASU8ITK24eCyvSREziTp
# dOmobHj6PAuPxID2GQRWivvFkVHCgQyURwXYGZGyyWAodnVCCuDfeg0Zl0yOnn76
# +ttw1Jwis2DuD0iYt2xtlHBuz2q5rYPiqfWNBzjLB5YUYIlUVe6zTxugbZcxaGkq
# I9zZgEt4xQISiwBMd4yMK/5PvLdelRu3hH906imI+qFT6KF/TyzIWwMJagnlyMrV
# J2o6WV3SWfz9dqA5sdUwVKFhV5UVXQIDAQABo4IDAjCCAv4wPgYJKwYBBAGCNxUH
# BDEwLwYnKwYBBAGCNxUIhuuse4XY6AqB9YMnhcedMILLymuBIIKdyUCFycMJAgFk
# AgEFMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMB
# Af8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFMym
# AjQ4sX+eXe17gEZrQWOfXzFlMB8GA1UdIwQYMBaAFIGzBwO656Nyuciocs96JTjz
# kI9AMIHyBgNVHR8EgeowgecwgeSggeGggd6Gga5sZGFwOi8vL0NOPUFLRy1DQSgx
# KSxDTj1BS0ctQ0EtMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
# LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9QUtHLERDPUxBTj9jZXJ0
# aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJp
# YnV0aW9uUG9pbnSGK2h0dHA6Ly9wa2kuYWtnLmxhbi9DZXJ0RW5yb2xsL0FLRy1D
# QSgxKS5jcmwwgbQGCCsGAQUFBwEBBIGnMIGkMIGhBggrBgEFBQcwAoaBlGxkYXA6
# Ly8vQ049QUtHLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxD
# Tj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPUFLRyxEQz1MQU4/Y0FDZXJ0
# aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkw
# MAYDVR0RBCkwJ6AlBgorBgEEAYI3FAIDoBcMFWVsc2hhbmktYWRtaW5AQUtHLkxB
# TjBOBgkrBgEEAYI3GQIEQTA/oD0GCisGAQQBgjcZAgGgLwQtUy0xLTUtMjEtNTM3
# MzE5Mzg2LTExNTk5NDk5NDUtMzIzNzMzMzY5MS0yMTE4MA0GCSqGSIb3DQEBCwUA
# A4IBAQAcrNJxlq5heLWdSDR+jSM5ikBExEmf2ANtFXi7qyAadQp77iy75Lm8xsyC
# EuzdoBw53meFvWT8MxlcHbx8P1hOuFkz3tafwVwFLhA3ZH4RyBa5BtjNxyGb573G
# LyL33inXBMHtkFsPq5aXgjrHHODxOpubWMk27WxaqtrtH+xjCQ+R9d1ZVOTWvQGC
# RunLzyP4KBwdz0xZnBKgbzlS4dtCSE5dB8vxhyGv9sXX+iwbbN82CpGiP0WgrfM6
# O7B4CWp3Sy9TJKcxDtICXKavLqlRyT1A3uzkluegvXDhS482hKH41KVzBrMjlxoQ
# aXkyQQTLqUzLhbAf9x97YD/1juzWMIIGeDCCBGCgAwIBAgITMQAAAASSbjqvdwYv
# lgAAAAAABDANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDEwdST09ULUNBMB4XDTI1
# MDIyMDEzMjgzNVoXDTM1MDIyMDEzMzgzNVowOzETMBEGCgmSJomT8ixkARkWA0xB
# TjETMBEGCgmSJomT8ixkARkWA0FLRzEPMA0GA1UEAxMGQUtHLUNBMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5B4+hbXqm/XI9+96lFwRKh7JQDPB7p0t
# hDNiJi3z5Z4F8DBHpcDFJOaNvFwq/+IxTajl6N1ontJdKDGwbmRPa/d0ODUsqPRl
# S2fU6x+kHh3FrIqkH8Idxd024EugseQm4SVNumT9b3zu+fHmk9PqN9RPgb+8uUq1
# kXVlyJxKcRRiMg++u/Eb6MT6T9dlsbdfobJ7xhZh2hILmEjs8i/nhq1chw+1SgdH
# rMewOXkWD0f9rfrMIKOgdX9NMbFunTdkM8qbV7n89PDtUBgyUuL2SCn0k4/5wB8N
# crAh5UhUAlLenQm+CA1ksw0ZSbM72vFvAzY94knkNbv1JtPTPYWBLQIDAQABo4IC
# nDCCApgwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQU4bCz4OXE
# 13bBeMT7cKO2CODz+9AwHQYDVR0OBBYEFIGzBwO656Nyuciocs96JTjzkI9AMBkG
# CSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8E
# BTADAQH/MB8GA1UdIwQYMBaAFGlPdDhdyuUTTyIO3Jl8k9hgR/q/MIHsBgNVHR8E
# geQwgeEwgd6ggduggdiGgapsZGFwOi8vL0NOPVJPT1QtQ0EsQ049Um9vdC1DQSxD
# Tj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049
# Q29uZmlndXJhdGlvbixEQz1BS0csREM9TEFOP2NlcnRpZmljYXRlUmV2b2NhdGlv
# bkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIYpaHR0
# cDovL3BraS5ha2cubGFuL0NlcnRFbnJvbGwvUk9PVC1DQS5jcmwwgfQGCCsGAQUF
# BwEBBIHnMIHkMD0GCCsGAQUFBzAChjFodHRwOi8vcGtpLmFrZy5sYW4vQ2VydEVu
# cm9sbC9Sb290LUNBX1JPT1QtQ0EuY3J0MIGiBggrBgEFBQcwAoaBlWxkYXA6Ly8v
# Q049Uk9PVC1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
# U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1BS0csREM9TEFOP2NBQ2VydGlm
# aWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MA0G
# CSqGSIb3DQEBCwUAA4ICAQAQeNPKg2bY3IBFcyHKoz7UiB8BKyl/50dU6MKKAw4+
# lHGPSdE5WRbjl6CrHkIDlzudohSbaNUTbE2kVOa8vLuJFbCyPBxq9fkVHDtTrPyF
# VSQwf4XjbM5blNMKvc3RUjLCFFuiFeGcWXqovo1BpqJVFqmV6tECcnyAHi6AGBsc
# 2Nsv9YXwJfbYD3qGdk4ueX6F4hF9tbD9vwQ6I1SoCa3JiDqnIvz+jTP+6yKUc0ux
# 7bFW2gxjqzK6p8AiRZvDVE+K/5lGrK7juTdSn4kr1538ZgcX0Zoh27jtvYQEMH4w
# Fc4ZVaMkkQP86h0ic+My+EIBZrLrSs6tPcb+mxt9ds5IQ8rx5VENz2QMuNTqKPk1
# NEAz4Bs1U2sDubAFZNdRCbb8QwJoIieGMKp1FtUnD8kk00eg+lbKAc7sjQQsZKIX
# WD1codu7iKZ70+m2B7DSWMtkJWwS7URRGtgI3BHEOAHdgbod6Wdru0rNBLkKH8bb
# n9LDUn7xOG9MKSjNNwDSyf+3zcVKWXC4Z6foT3SJe8y84BpHclHJMZ0pdyTldRbT
# PCIEaizkJPa5cz3gqSBtCtjENt1F1641puBdWgg+fVyJD0MvPZ5vJtiLz0gZZrvY
# PMUjoyHdcYN9VtCp0fZ1NBV/wr1kTXnj8a+ni3x8TiLDRaL3Cx6lJrqgNYKIDcLo
# QzCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBU
# cnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysdduj
# Rmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S
# 9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+
# 42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg6
# 2IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21
# Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8
# y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQ
# NfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gao
# u30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6g
# qztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJD
# psZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D
# 8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEA
# MB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC
# 0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYB
# BQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSG
# Mmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQu
# Y3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0B
# AQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6F
# TGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mC
# efSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57m
# QfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9
# ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dB
# wp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdq
# fMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2
# puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAO
# k5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL
# 0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBun
# vAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggbtMIIE
# 1aADAgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNI
# QTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHf
# yjfMGUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPx
# NyFPJIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpk
# BaMUNg7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFv
# ZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1zn
# OM8odbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8f
# cpK40uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ah
# fvAk12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUD
# y9Z2hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9
# w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTn
# nkrT3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKa
# cJ+A9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7
# /PIx7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ
# 7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYI
# KwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0
# LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEu
# Y3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0Ex
# LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcN
# AQELBQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF
# 0RkP2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKq
# dT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbU
# UO75ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTe
# HihsQyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG
# 7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NB
# qycz0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6
# +iX8MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaA
# yBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyP
# ehwJVxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3F
# NwFlTxq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMYIFLjCC
# BSoCAQEwUjA7MRMwEQYKCZImiZPyLGQBGRYDTEFOMRMwEQYKCZImiZPyLGQBGRYD
# QUtHMQ8wDQYDVQQDEwZBS0ctQ0ECEysAAABujLf17Ok1o48AAQAAAG4wDQYJYIZI
# AWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAv
# BgkqhkiG9w0BCQQxIgQgS4EDsrdHAhCySE01SFM0yWupKhlxt5iJwsiR8f3AOmgw
# DQYJKoZIhvcNAQEBBQAEggEAPE8nzUPYclsZly8zOwMMK6SIlsmlepBTkQknneeD
# 41R7JSfBw6I3bp3M0OZrnKZDncnlACxFNeWMMiCyO05g70uHjzMZ13AFLJaEHqa+
# VVED6IafeGwM7/GuCwDfxxu6ufPxYIOZpXy+6kIb5PT5PJdumvWOXyabJxQ+V51B
# bBbV4BI4K0wPaGsZnD2WWaWJ954ugBk19DCSuG3epFXH0vXFZBJdban7eh0C5tJs
# 5nqv2aKHC4N1hLbRa+ctmsHinNKo5CYtDf4oqMUTBFaNytaL8HJdzObI6wuqm3MA
# lR0KUh98CUuYlpqJtrERnEk2111raYIRtFr8Y7G5dFFXvaGCAyYwggMiBgkqhkiG
# 9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3Rh
# bXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgw
# DQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqG
# SIb3DQEJBTEPFw0yNTA5MTExODU2MzdaMC8GCSqGSIb3DQEJBDEiBCCqsLUF9OhK
# dnohCTwuHtWWhWo9MKqrIEZzkHY6xRNLuTANBgkqhkiG9w0BAQEFAASCAgBgEOMQ
# xkG3mBFZ3o3ApUUW2K34zZ58ifPPJhTl8IRS7PJOEdnYRp1sWhJsDqyYITvgC5K9
# MNXd8kSholPW7C2RExPkDRc9Q3fQeeHG8bPGtcFaXVtsA0ugLJwaRx3srbt9lC8q
# Bebc5S/n4qVFoU3/oMbT85ajQPUwfiuV86GnZepD/wgjYMMSval/zBnHGpDGiGjv
# Ypli71m61dEN3SbUm9uaFff9cWUXhwyWUkIt1ucN7jhzbBGKrfFoSGrT45PwgKg/
# LJjE8AZxvQuaZFqGK3pk62bKovPh/yfybtIZLEt3w4Xz/Vgc/7ghTqHw8JQJYWYi
# naYPCcsNyhbn4lBKnvhyHBYxXu3/YZlAbzuUn6cjbrUpZ8f46XBira7+ntOM8k2T
# /LT5mdIHMDtTlQ43XjORsLTIlhdXT8F7Kw7E6Tyrll37QXrdbghxBovcKPUtH4CC
# ha0FGb1Gu7qNQWEs14OWa02pd5/+LBKvmzMzudIAZ8bLoIqq4L5P1rlUxuNM6uCn
# muaNgChrn5IVeCkyLyf0O0V/Wjdhv3IcIy6HtHLb4+MMHCv1pUOTKQJ1+CrLbt0Q
# s1A1RNEcXtPkPPwkPS8eRZ/zBrDafI1NDuw6gBh1+CMaCtsrrIQ3rm/QKFf0EgGF
# cfwqn8K/OYGVyC3XsmKMTX3o7AHcaaN6z1VZMw==
# SIG # End signature block


