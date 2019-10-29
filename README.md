# Event ID for RDP

RDP structure step by step

Network Connection (EventID- 1149)- NOT AN AUTHENTICATION. Someone launched an RDP client, specified the target machine (possibly with a username and domain), and hit enter to make a successful network connection to the target. Nothing more, nothing less.

Authentication (EventID- 4624) - User successfully logged on to this system with the specified TargetUserName and TargetDomainName from the specified IpAddress.

Logon (EventID- 21,22 ) - Indicates successful RDP logon and session instantiation, so long as the “Source Network Address” is NOT “LOCAL”.

Session Disconnect / re-connect (EventID- 24,25,39,40, 4778, 4779) - The user has disconnected from an RDP session, so long as the “Source Network Address” is NOT “LOCAL”.

Logoff (EventID- 23, 4634, 4647, 9009) - The user initiated a formal system logoff (versus a simple session disconnect).

