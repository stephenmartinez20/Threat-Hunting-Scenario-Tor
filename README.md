# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/stephenmartinez20/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “marty” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2026-05-09T15:29:01.6036215Z. These events began at: 2026-05-09T15:04:53.3597025Z. .

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "edr-test-marty"  
| where InitiatingProcessAccountName == "marty"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-05-09T15:04:53.3597025Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1229" height="366" alt="image" src="https://github.com/user-attachments/assets/a7ddd11a-41de-4e94-908d-5366325f9bae" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents Table for ANY ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.13.exe”. Based on the logs returned, At 2026-05-09T15:06:36.0806205Z, an employee named “Marty” on the “edr-test-marty” device ran the file tor-browser-windows-x86_64-portable-15.0.13.exe from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "edr-test-marty"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.13.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1420" height="74" alt="image" src="https://github.com/user-attachments/assets/df80f056-b45c-4262-a7f4-b75322dd36fd" />



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "marty" actually opened the TOR browser. There was evidence that they did open it at  2026-05-09T15:07:08.9067449Z. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "edr-test-marty"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1412" height="561" alt="image" src="https://github.com/user-attachments/assets/8b64ade5-bf52-47ed-a424-17a0083635e3" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the Device NetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2026-05-09T15:07:19.8160837Z, an employee named “Marty” on the “edr-test-marty” device successfully established a connection to the remote IP address 212.227.104.242 on port 9001. The connection was initiated by the process tor.exe, located in the folder c:\users\marty\desktop\tor browser\browser\torbrowser\tor\tor.exe. There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "edr-test-marty"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1585" height="297" alt="image" src="https://github.com/user-attachments/assets/719a698d-eff1-4d6d-b203-62876033db12" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-05-09 15:04:53.3597025Z`
- **Event:** The user "marty" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.13.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\marty\Downloads\tor-browser-windows-x86_64-portable-15.0.13.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-05-09 15:06:36.0806205Z`
- **Event:** The user "marty" executed the file `tor-browser-windows-x86_64-portable-15.0.13.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.13.exe /S`
- **File Path:** `C:\Users\marty\Downloads\tor-browser-windows-x86_64-portable-15.0.13.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-05-09 15:07:00Z`
- **Event:** User "marty" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\marty\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-05-09 15:07:08.9067449Z`
- **Event:** A network connection to IP `212.227.104.242` on port `9001` by user "marty" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\marty\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-05-09T11:07:17Z` - Connected to `23.191.200.23` on port `443`.
  - `2026-05-09T11:07:30Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "marty" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-05-09T15:29:01.6036215ZZ`
- **Event:** The user "marty" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\marty\Desktop\tor-shopping-list.txt`

---

## Summary

The investigation confirmed that user marty on endpoint edr-test-marty downloaded, installed, launched, and used the Tor Browser on 2026-05-09.
The activity began with Tor-related file creation events beginning at 15:04:53 UTC, followed by execution of the Tor Browser portable installer from the Downloads directory at 15:06:36 UTC. Shortly after execution, Tor Browser components including tor.exe and firefox.exe were launched from the desktop-installed Tor Browser directory.
Process telemetry confirmed initialization of the Tor service, including SOCKS proxy configuration and Tor control port setup, followed by successful launch of the Tor Browser application.
Network telemetry confirmed outbound connectivity to a remote host over TCP port 9001, a port commonly associated with Tor relay communications, demonstrating that the Tor client successfully connected to the Tor network.
Subsequent activity showed continued Tor Browser operation through additional Firefox child processes and encrypted outbound connections over port 443.
The final observed Tor-related event was the creation of a desktop file named tor-shopping-list.txt at 15:29:01 UTC.
Overall, the evidence strongly supports that the user intentionally downloaded, installed, and actively used the Tor Browser on the endpoint during the identified timeframe

---

## Response Taken

TOR usage was confirmed on endpoint edr-test-marty by the user marty. The device was isolated and the user's direct manager was notified. 

---
