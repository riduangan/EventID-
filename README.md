# Event ID for RDP

RDP structure step by step

**Network Connection (EventID- 1149)**- THIS IS NOT AN AUTHENTICATION. Someone launched an RDP client, specified the target machine (possibly with a username and domain), and hit enter to make a successful network connection to the target. Nothing more, nothing less.

**Authentication (EventID- 4624)** - User successfully logged on to this system with the specified TargetUserName and TargetDomainName from the specified IpAddress.

**Logon (EventID- 21,22)** - Indicates successful RDP logon and session instantiation, so long as the “Source Network Address” is NOT “LOCAL”.

**Session Disconnect / re-connect (EventID- 24, 25, 39, 40, 4778, 4779)** - The user has disconnected from an RDP session, so long as the “Source Network Address” is NOT “LOCAL”.

**Logoff (EventID- 23, 4634, 4647, 9009)** - The user initiated a formal system logoff (versus a simple session disconnect).

Historically, the main artifact on a source system (the system connecting to another system via RDP) was a prefetch entry for mstsc.exe (the RDP client executable) – namely MSTSC.EXE-462193BE.pf. 

However, I’ve recently discovered another source of Event ID’s that provide indication and information on RDP connections to other systems. These events lie within the Microsoft-Windows-TerminalServices-RDPClient/Operational log (location on disk is %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx). 

When a source machine attempts to connect to a target, various Event ID’s are logged here indicating the name/IP of the target as well as various related connection and disconnection messages which can also be helpful when investigating a system that is the source of RDP connections to other machines.

https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/

# Event ID for Clearing Windows Logs

**"Security"** and [event_code] in [1100, 1102]) or
**"System"** and [event_code] == 104)

# Event ID for Disabling Windows Security Tools

log_name == "System" AND
event_code == "7036"
param1 in ["Windows Defender", "Windows Firewall"] AND

param2 == "stopped"
