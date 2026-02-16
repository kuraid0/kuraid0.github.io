---
title: "HackTheBox Sherlock: Campfire-1"
date: 2026-02-14
categories: [HackTheBox Sherlocks Writeup, CDSA Track]
tags: [dfir, htb-sherlock, kerberoasting, active-directory, event-logs, powerShell, prefetch]
image:
  path: /assets/img/htb-sherlocks/campfire-1/campfire-1.png
---

## Sherlock Scenario

Alonzo Spotted Weird files on his computer and informed the newly assembled SOC Team. Assessing the situation it is believed a Kerberoasting attack may have occurred in the network. It is your job to confirm the findings by analyzing the provided evidence.

---

## Artefacts provided

The following evidence has been provided for analysis:

1. Security Logs from the Domain Controller  
2. PowerShell-Operational Logs from the affected workstation  
3. Prefetch Files from the affected workstation  

---

Before beginning the investigation, the provided forensic artifacts were converted into CSV format to enable structured analysis and timeline correlation.

Converting logs into CSV format allows easier filtering, sorting, and cross-referencing of events using forensic timeline tools.

---

## Tools Used

- **EvtxECmd.exe** – For parsing Windows Event Log (.evtx) files  
- **PECmd.exe** – For parsing Windows Prefetch files  
- **Timeline Explorer** (Eric Zimmerman) – For event filtering and timeline correlation  

---

## Parsing Windows Event Logs

The `.evtx` files (Security Logs and PowerShell-Operational Logs) were converted into CSV format using **EvtxECmd.exe**.

```powershell
./EvtxECmd.exe -f "path_to_evtx_file.evtx" --csv "output_directory" --csvf output_filename.csv
```
![](/assets/img/htb-sherlocks/campfire-1/evtxecmd-securitycsv.png)
![](/assets/img/htb-sherlocks/campfire-1/evtxecmd-powershell.png)

## Parsing Prefetch Files

To analyze application execution artifacts from the affected workstation, the Prefetch directory was parsed using PECmd.exe.

```powershell
./PECmd.exe -d "path_to_prefetch_directory" --csv "output_directory" --csvf prefetch.csv
```
![](/assets/img/htb-sherlocks/campfire-1/pecmd-prefetch.png)

![](/assets/img/htb-sherlocks/campfire-1/csvoutput.png)

---

## Task 1

### Question
![](/assets/img/htb-sherlocks/campfire-1/task1-question.png)

**Analyzing Domain Controller Security Logs, can you confirm the UTC date & time when the kerberoasting activity occurred?**

---

### Analysis

To determine when the Kerberoasting activity occurred, I analyzed Kerberos-related events from the parsed `security.csv` file using Timeline Explorer.

I filtered for **Event ID 4769** (A Kerberos service ticket was requested), as this event is directly associated with Ticket Granting Service (TGS) requests — a key indicator in Kerberoasting attacks.

![](/assets/img/htb-sherlocks/campfire-1/4679-kerberoasting.png)

During the review, I identified a suspicious entry where the **Ticket Encryption Type was 0x17 (RC4)**. RC4 encryption is commonly leveraged in Kerberoasting attacks because it is weaker and easier to crack offline compared to modern Kerberos encryption standards.

The event was generated from a user account, which aligns with typical Kerberoasting behavior where an attacker requests service tickets for offline password cracking.

The findings were validated by cross-checking the event details directly in Event Viewer to confirm the timestamp and encryption type.

![](/assets/img/htb-sherlocks/campfire-1/eventviewer-4769.png)

---

## *For Tasks 2 and 3, the answers can be found in the screenshot above.*

## Task 2

### Question
![](/assets/img/htb-sherlocks/campfire-1/task2-question.png)

**What is the Service Name that was targeted?**

![](/assets/img/htb-sherlocks/campfire-1/servicename.png)

---

## Task 3

### Question
![](/assets/img/htb-sherlocks/campfire-1/task3-question.png)

**It is really important to identify the Workstation from which this activity occurred. What is the IP Address of the workstation?**

![](/assets/img/htb-sherlocks/campfire-1/ipaddress.png)

---

## Task 4

### Question
![](/assets/img/htb-sherlocks/campfire-1/task4-question.png)

**Now that we have identified the workstation, a triage including PowerShell logs and Prefetch files are provided to you for some deeper insights so we can understand how this activity occurred on the endpoint. What is the name of the file used to Enumerate Active directory objects and possibly find Kerberoastable accounts in the network?**

---

### Analysis

To investigate further attacker activity, I first reviewed the PowerShell Operational logs directly in Event Viewer and then analyzed the parsed `powershell-operational.csv` file in Timeline Explorer, focusing on suspicious PowerShell events.

One notable entry was **Event ID 4100 (Executing Pipeline)**, which contained the following error message:

> File C:\Users\alonzo.spire\Downloads\powerview.ps1 cannot be loaded because running scripts is disabled on this system.

From this message, it is clear that the attacker attempted to execute **powerview.ps1**, a well-known PowerShell-based enumeration tool commonly used in Active Directory reconnaissance and Kerberoasting attacks. However, the execution failed due to PowerShell execution policy restrictions.
![](/assets/img/htb-sherlocks/campfire-1/eventviewer-4100.png)

Since the script execution was blocked, the next event shows **Event ID 4104 (Execute a Remote Command)**, where the attacker used:
```powershell
powershell -ep bypass
```
![](/assets/img/htb-sherlocks/campfire-1/eventviewer-4104.png)

The `-ep bypass` flag is used to override PowerShell execution policy restrictions, allowing scripts to run without being blocked.

Shortly after, multiple **Event ID 4104** entries confirm that the attacker successfully executed:

![](/assets/img/htb-sherlocks/campfire-1/timelineexplorer.png)

---

## Task 5

### Question
![](/assets/img/htb-sherlocks/campfire-1/task5-question.png)

**When was this script executed? (UTC)**

The answer to this question can be observed in the screenshot shown in the previous section.
![](/assets/img/htb-sherlocks/campfire-1/timelineexplorer-scriptexecutedtime.png)

---

## Task 6

### Question
![](/assets/img/htb-sherlocks/campfire-1/task6-question.png)

**What is the full path of the tool used to perform the actual kerberoasting attack?**

---

### Analysis

To determine the tool used to perform the Kerberoasting attack, I analyzed the parsed `prefetch.csv` file using Timeline Explorer.

Prefetch files record application execution artifacts, including executable names and execution timestamps. By correlating the Prefetch data with the Kerberoasting activity identified in Task 1 (**2024-05-21 03:18:09 UTC**), I located a matching execution event.

![](/assets/img/htb-sherlocks/campfire-1/rubeus.png)

The Prefetch entry shows that **RUBEUS.EXE** was executed at:

**2024-05-21 03:18:08 UTC**

This execution occurred one second before the suspicious Kerberos service ticket request identified in Task 1, strongly indicating that the tool was used to perform the attack.

The full path of the executable can be observed in the screenshot above.

---

## Task 7

### Question
![](/assets/img/htb-sherlocks/campfire-1/task7-question.png)

**When was the tool executed to dump credentials? (UTC)**

The answer is shown in the previous screenshot.

Based on the Prefetch analysis, the credential-dumping tool was executed at:

**2024-05-21 03:18:08 UTC**

This timestamp closely aligns with the Kerberos service ticket request identified earlier, further confirming the sequence of events during the Kerberoasting attack.

---

## Conclusion

The investigation confirms that a Kerberoasting attack occurred in the environment.  

Analysis of Event ID 4769 revealed a suspicious RC4-encrypted service ticket request, while PowerShell logs showed the execution of `powerview.ps1`. Prefetch artifacts confirmed that `RUBEUS.EXE` was executed at **2024-05-21 03:18:08 UTC**, closely aligning with the Kerberos ticket request.

The timeline correlation across logs validates that the attacker successfully performed the Kerberoasting attack.

---

