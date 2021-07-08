# Microsoft Windows Event ID to monitor

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

# Event ID for Scheduled Task 

This Event can be found under **Application and Service Logs > Microsoft > Windows > TaskScheduler**

201 (Task registered)
140 (Task Modified)
141 (Task registered)
142 (Task disabled)
129 (Task Launched)

Some other useful Event IDs which arguably provide more information than the above but may not be enabled on an OS include the below Security Event Logs:

4698 (Scheduled Task Creation)
4702 (Scheduled Task Modified)
4699 (Scheduled Task Deleted)
4701 (Scheduled Task Disabled)
4700 (Scheduled Task Enabled)

# Event ID for Sucessful Login Variation (4624)
- Non allowed account
  Within your business you may have accounts which you do not want used for logging on directly (either via keyboard or virtual session)
  Most commonly this will be service and computer accounts.

  Event ID = 4624 **AND**
  Logon Type is 2 or 10 (See more about logon types here – http://techgenix.com/logon-types/ **AND**
  Username matches expression ^SVC.* or .*\$$ (This is looking for service or computer accounts)
  
- Logons Directly to Domain Controller
  event id = 4624 **AND**
  logon type is 2 or 10 **AND**
  Login targer is YOUR DC **AND**
  NOT when user is DC ADMIN

- Pass the Hash
  Event ID = 4624 **AND**
  logon type is 3 **AND**
  Logon process is NtLmSsp **AND**
  SubjectUserSID is S-1-0-0 **AND**
  KeyLength is 0
  
 - Overpass the Hash
  event id = 4624 **AND**
  logon type is 9 **AND**
  Logon process is seclogo
  


# Event ID for Failed Login Variation (4625)
- Failed logins for User
  event id = 4625 **AND** 
  X number of failed logins in X minutes with the same username
  
- Password Spraying
  event id = 4625 **AND** 
  same source **AND** 
  2 or more username within x minutes
  
- Attempted to use disabled account
  event id = 4625 **AND** 
  sub Status Code is 0xC0000072
  
- Attempted to use expired account usage
  event id = 4625 **AND** 
  Sub Status Code is 0xC0000193
  
 # Event ID for Malicious AD SYNC (4662)
- Typical behavious soomeone tries to use Mimikatz to sync DC
  event it = 4662 **AND**
  Properties = Replicating Directory Changes All* OR 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* **AND**
  Not when account is NT Authority or matching expression .*\$$

- AD replication from non machine account
  event id = 4662 **AND** 
  AccessMask is 0x100 **AND**
  Properties contains ‘1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 OR ‘1131f6ad-9c07-11d1-f79f-00c04fc2dcd2’ OR ’89e95b76-444d-4c62-991a-0facbeda640c
  
- Extracting backup key
  event id = 4662 **AND**
  object type = SecretObject **AND**
  AccessMask is 0x2 **AND**
  ObjectName is BCKUPKEY
  
- AD sync via new SPN (Service Principle Name)
  event id = 4742 **AND**
  Service Principal Name matches expression *GC/*

# Advanced Auditing Policies mapping to the Event ID
On Windows Server run "gpmc.msc" to bring up the editor and navigate to the Advanced Auditing Policies.
Below are the correspondence of the Event ID to the specific Audit setting.

Group Policy Group	Group Policy Option	Event IDs
- Account Logon	Audit Credential Validation	4774, 4775, 4776, 4777
- Audit Kerberos Authentication Service	4768, 4771, 4772
- Audit Kerberos Service Ticket Operations	4769, 4770
- Audit Other Account Logon Events	4649, 4778, 4779, 4800, 4801, 4802, 4803, 5378, 5632, 5633
- Account Management	Audit Application Group Management	4783, 4784, 4785, 4786, 4787, 4788, 4789, 4790
-	Audit Computer Account Management	4741, 4742, 4743
-	Audit Distribution Group Management	4744, 4745, 4746, 4747, 4748, 4749, 4750, 4751, 4752, 4753, 4759, 4760, 4761, 4762
-	Audit Other Account Management Events	4782, 4793
-	Audit Security Group Management	4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764
-	Audit User Account Management	4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4765, 4766, 4767, 4780, 4781, 4794, 5376, 5377
- Detailed Tracking	Audit DPAPI Activity	4692, 4693, 4694, 4695
-	Audit Process Creation	4688, 4696
-	Audit Process Termination	4689
-	Audit RPC Events	5712
- DS Access	Audit Detailed Directory Service Replication	4928, 4929, 4930, 4931, 4934, 4935, 4936, 4937
-	Audit Directory Service Access	4662
-	Audit Directory Service Changes	5136, 5137, 5138, 5139, 5141
-	Audit Directory Service Replication	4932, 4933
- Logon/Logoff	Audit Account Lockout	4625
-	Audit IPsec Extended Mode	4978, 4979, 4980, 4981, 4982, 4983, 4984
-	Audit IPsec Main Mode	4646, 4650, 4651, 4652, 4653, 4655, 4976, 5049, 5453
-	Audit IPsec Quick Mode	4977, 5451, 5452
-	Audit Logoff	4634, 4647
-	Audit Logon	4624, 4625, 4648, 4675
-	Audit Network Policy Server	6272, 6273, 6274, 6275, 6276, 6277, 6278, 6279, 6280
-	Audit Other Logon/Logoff Events	4649, 4778, 4779, 4800, 4801, 4802, 4803, 5378, 5632, 5633
-	Audit Special Logon	4964
- Object Access	Audit Application Generated	4665, 4666 ,4667, 4668
-	Audit Certification Services	4868, 4869, 4870, 4871, 4872, 4873, 4874, 4875, 4876, 4877, 4878, 4879, 4880, 4881, 4882, 4883, 4884, 4885, 4886 ,4887, 4888, 4889, 4890, 4891, 4892, 4893, 4894, 4895, 4896, 4897, 4898
-	Audit Detailed File Share	5145
-	Audit File Share	5140, 5142, 5143, 5144, 5168, 4663
-	Audit File System	4664, 4985, 5051
-	Audit Filtering Platform Connection	5031, 5140, 5150, 5151, 5154, 5155, 5156, 5157, 5158, 5159
-	Audit Filtering Platform Packet Drop	5152, 5153
-	Audit Handle Manipulation	4656, 4658, 4690
-	Audit Kernel Object	4659, 4660, 4661, 4663
-	Audit Other Object Access Events	4671, 4691, 4698, 4699, 4700, 4701, 4702 ,5148, 5149, 5888, 5889, 5890
-	Audit Registry	4657, 5039
-	Audit SAM	4659, 4660, 4661, 4663
- Policy Change	Audit Audit Policy Change	4715, 4719, 4817, 4902, 4904, 4905, 4906, 4907, 4908, 4912
-	Audit Authentication Policy Change	4713, 4716, 4717, 4718, 4739, 4864, 4865, 4866, 4867
-	Audit Authorization Policy Change	4704, 4705, 4706, 4707, 4714
-	Audit Filtering Platform Policy Change	4709, 4710, 4711, 4712, 5040, 5041, 5042, 5043, 5044, 5045, 5046, 5047, 5048, 5440, 5441, 5442, 5443, 5444, 5446, 5448, 5449, 5450, 5456, 5457, 5458, 5459, 5460, 5461, 5462, 5463, 5464, 5465, 5466, 5467, 5468, 5471, 5472, 5473, 5474, 5477
-	Audit MPSSVC Rule-Level Policy Change	4944, 4945, 4946, 4947, 4948, 4949, 4950, 4951, 4952, 4953, 4954, 4956, 4957, 4958
-	Audit Other Policy Change Events	4670, 4909, 4910, 5063, 5064, 5065, 5066, 5067, 5068, 5069, 5070, 5447, 6144, 6145
- Privilege Use	Audit Non-Sensitive Privilege Use	4672, 4673, 4674
-	Audit Sensitive Privilege Use	4672, 4673, 4674
-	Audit Other Privilege Use Events	N/A
- System	Audit IPsec Driver	4960, 4961, 4962, 4963, 4965, 5478, 5479, 5480, 5483, 5484, 5485
-	Audit Other System Events	5024, 5025, 5027, 5028, 5029, 5030, 5032, 5033, 5034, 5035, 5037, 5058, 5059, 6400, 6401, 6402, 6403 ,6404, 6405, 6406, 6407, 6408
-	Audit Security State Change	4608, 4609 ,4616, 4621
-	Audit Security System Extension	4610, 4611, 4614, 4622, 4697
-	Audit System Integrity	4612, 4615, 4618, 4816, 5038, 5056, 5057, 5060, 5061, 5062, 6281
