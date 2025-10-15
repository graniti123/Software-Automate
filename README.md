🖥️ PowerShell-Installationsskript – Bedienungsanleitung
1️⃣ Vorbereitung

PowerShell-Version prüfen
Das Skript benötigt PowerShell 5.1 oder höher (Windows 10/11).

$PSVersionTable.PSVersion


Administrative Rechte

Skript muss als Administrator gestartet werden.

Ohne Adminrechte können viele Installationen fehlschlagen.

Temporäre Pfade

Standard: C:\Temp

Prüfen, ob der Pfad existiert oder im Skript anpassen.

2️⃣ Anpassungen vor dem Einsatz
🔹 Logs-Pfad
$LogPath = "\\fileserver\Software-Logs\Büro-Software-Install.log"


Auf lokalen Pfad anpassen, z. B. C:\Temp\Büro-Software-Install.log

Schreibrechte prüfen

🔹 Quellen für Software
Software	Pfad
Office 2019	\\deinserver\Software\Office_2019\	                                  🟦

Citrix Workspace	\\deinserver\Software\CitrixWorkspace\CitrixWorkspace.exe	      🟪

MyApps Script	\\deinserver\Skripte\myapps.ps1	                                   🟩

EVA Starter	\\deinserver\Software\EVA_Starter\EVA_Start.jnlp	                    🟨 

Windream Client	\\deinserver\Software\Windream\Client\	                          🟥


Alle Pfade müssen erreichbar sein (Netzwerkfreigaben)

🔹 Choco-Apps

Standardinstallationen:

App	Icon
Firefox	                                                                          🦊
Notepad++	                                                                        📝
Java	                                                                            ☕
Greenshot                                                                        	📸
7zip	                                                                            📦

Bei Bedarf Apps hinzufügen oder entfernen.

🔹 Bitdefender

URL & CompanyHash prüfen

Optional: nur auf gewünschten Systemen installieren

🔹 Office Shortcuts

Pfade auf Standardinstallationen gesetzt

Prüfen bei anderen Office-Versionen

🔹 Code-Signing (optional)
Set-AuthenticodeSignature -FilePath "Pfad\zum\Skript.ps1" -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)

3️⃣ Ausführung

PowerShell als Administrator starten

Skript ausführen:

powershell.exe -ExecutionPolicy RemoteSigned -File "Pfad\zum\Skript.ps1"

🛠️ Schritte des Skripts

Prüft und installiert Chocolatey

Installiert definierte Choco-Apps

Installiert Office 2019, falls nicht vorhanden

Erstellt Office-Shortcuts auf dem öffentlichen Desktop

Führt MyApps, EVA Starter und Citrix Workspace Installation aus

Installiert Bitdefender (optional)

Installiert Windream Client zuletzt

Bereinigt temporäre Dateien in C:\Temp

Alle Aktionen werden im Log protokolliert

4️⃣ Hinweise & Risiken

Nie auf Produktivsystemen ohne vorherige Tests ausführen

Prüfen: Pfade, Versionskompatibilität, Schreibrechte

Einige Installationen (Office, Bitdefender) benötigen Zeit und ggf. Neustart

✅ Checkliste vor Einsatz
1. System & Rechte

 PowerShell-Version ≥ 5.1 geprüft

 Skript mit Administratorrechten gestartet

 Vorhandene C:\Temp oder angepasster temporärer Pfad

2. Log-Dateien

 $LogPath existiert oder angepasst

 Schreibrechte auf Log-Verzeichnis geprüft

3. Software-Quellen

 Office 2019 Quellordner korrekt gesetzt

 Citrix Workspace Installer korrekt gesetzt

 MyApps Script korrekt gesetzt

 EVA Starter Datei korrekt gesetzt

 Windream Client Quellordner korrekt gesetzt

 Alle Pfade auf Netzwerkfreigaben erreichbar

4. Installationspakete

 Choco-Apps geprüft und angepasst

 Office Shortcuts Pfade korrekt gesetzt

 Bitdefender URL & CompanyHash geprüft

5. Sicherheits- & Richtlinienchecks

 Skript ggf. digital signiert

 Antiviren-/Security-Software überprüft

 Testlauf auf Testsystem durchgeführt

6. Sonstiges

 Netzwerkverbindung stabil

 Genug Speicherplatz auf C:\ vorhanden

 Benutzer informiert, dass Installation mehrere Minuten dauert

 Neustart möglich/geplant (Office oder Bitdefender)
