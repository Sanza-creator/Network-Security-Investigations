# Network Security Investigations

Two hands-on investigations analysing network traffic and malware behaviour, built to practice the core workflow of a SOC/security analyst: capture → analyse → conclude.

---

## 1. TCP Session Investigation (Wireshark)

### Scenario
During a packet capture review, a TCP conversation on port 80 (`140.248.134.172 ↔ 192.168.0.53`) stood out — it was transferring large volumes of data with no HTTP visible in the packet list, raising the question of whether this was tunnelled or otherwise suspicious traffic.

### What I did
- Isolated the conversation using `tcp.stream eq 94` and followed the full TCP stream in Wireshark
- Identified the traffic as a legitimate `HTTP/1.1 206 Partial Content` response from `tlu.dl.delivery.mp.microsoft.com`, with a Content-Disposition header naming the payload `Microsoft.YourPhone_1.26072.255.0_neutral_~_8wekyb3d8bbwe.AppxBundle` — an app update delivered via Microsoft Delivery Optimization
- Confirmed the traffic was legitimate (not encrypted tunnelling) by matching headers (`MS-CV`, `MS-CorrelationID`, `Cache-Control: public, max-age=17280000`) to standard Windows Update/Microsoft Store behaviour
- Broadened the analysis capture-wide using the HTTP object list, finding dozens of `.cab` delta packages from `download.windowsupdate.com`, further objects from `dl.delivery.mp.microsoft.com`, and Edge extension update traffic from `msedge.b.tlu.delivery.mp.microsoft.com` — confirming the pattern was routine OS/browser background traffic, not an isolated anomaly
- Reviewed the I/O graph, identifying bursty traffic with spikes up to ~1,900 packets/second aligning with the bulk download activity
- Ran TCP analysis across the full capture: of 95,118 total packets, 3,581 (3.8%) were flagged — predominantly duplicate ACKs, out-of-order segments, and "previous segment not captured" notices concentrated during the busiest traffic windows, with **no zero-window conditions or sustained retransmission storms**

### Key finding
Port 80 traffic was confirmed as legitimate Windows Update, Microsoft Delivery Optimization, and Edge extension-update activity — not encrypted tunnelling. The 3.8% TCP error rate is consistent with normal Wi-Fi contention during a heavy bulk-download period rather than an underlying network fault, since the flagged packets were dominated by benign categories (out-of-order, duplicate ACK) rather than genuine data-loss indicators (zero-window, repeated fast retransmissions).

### Skills demonstrated
`Wireshark (stream following, HTTP object export, I/O graphs)` · `TCP/IP fundamentals` · `Distinguishing benign vs. anomalous traffic patterns` · `Evidence-based investigative conclusions`

### Screenshots
`[Insert: Follow TCP Stream view of stream 94, HTTP object export list, tcp.analysis.flags filtered view, I/O graph]`

---

## 2. ICEDID Malware Investigation (CyberDefenders)

### Scenario
Investigated a phishing-distributed ICEDID sample as part of CyberDefenders' Blue Team CTF challenge, simulating monitoring of an APT group's malware delivery infrastructure from a sample hash.

### What I did
- **File identification:** Submitted the sample hash to VirusTotal and identified the associated filename via the Details/Names section
- **Dropped-file analysis:** Used VirusTotal's Relations tab to trace dropped files and identified the malicious GIF payload (`3003[1].gif`, flagged Win32 DLL, 54/70 detections) deployed by the sample
- **Infrastructure mapping:** Reviewed Contacted URLs and identified **5 distinct domains** the malware queried to retrieve the additional GIF payload (including `columbia.aula-web.net`, `partsapp.com.br`, `metaflip.io`, `tajushariya.com`, `agenbolatermurah.com`)
- **Registrar attribution:** Cross-referenced the Contacted Domains table and identified **NameCheap Inc.** as the predominant registrar used to host the malicious `.com` infrastructure
- **Threat actor attribution:** Used MITRE ATT&CK (`attack.mitre.org/software/S0483`) to identify the associated group using this malware family as **TA551**
- **Execution analysis:** Reviewed a sandbox triage report's extracted malware config and identified the Windows API function (`URLDownloadToFileA`) used to fetch the GIF payload from the 5 identified domains during the Execution phase

### Key finding
The sample was a financially-motivated ICEDID banker/loader distributed by threat actor **TA551**, using `URLDownloadToFileA` calls to five NameCheap-registered domains to retrieve a disguised second-stage payload (`3003.gif`, actually a Win32 DLL).

### Skills demonstrated
`Malware analysis (VirusTotal, sandbox triage reports)` · `IOC identification (hashes, domains, URLs, registrars)` · `Threat intelligence mapping (MITRE ATT&CK)` · `Incident response methodology`

### Verified completion
Lab completed on CyberDefenders — [IcedID Blue Team CTF achievement](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/nsandile560/icedid/)


---

## Why these projects
Both exercises reflect the day-to-day of a SOC analyst: reading traffic and artifacts closely, forming a hypothesis, and backing it with evidence — including knowing when the answer is "this is normal" as much as when it's "this is malicious."
