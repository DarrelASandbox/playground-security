## About the Project

- OWASP top 10: Web Application Security for beginners
- Learn the OWASP top 10 common Cyber Security attacks! Apply cyber security principles and stop Cyber Security hackers!
- Soerin Bipat

  <ol>
    <li><a href="#injection">Injection</a></li>
    <li><a href="#broken-authentication">Broken Authentication</a></li>
    <li><a href="#sensitive-data-exposure">Sensitive Data Exposure</a></li>
    <li><a href="#xml-external-entities">XML External Entities</a></li>
    <li><a href="#broken-access-control">Broken Access Control</a></li>
    <li><a href="#security-misconfiguration">Security Misconfiguration</a></li>
    <li><a href="#cross-site-scripting-xss">Cross-Site Scripting (XSS)</a></li>
    <li><a href="#insecure-deserialization">Insecure Deserialization</a></li>
    <li><a href="#using-components-with-known-vulnerabilities">Using Components with Known Vulnerabilities</a></li>
    <li><a href="#insufficient-logging-and-monitoring">Insufficient Logging And Monitoring</a></li>
    <li><a href="#insufficient-attack-protection">Insufficient Attack Protection</a></li>
    <li><a href="#cross-site-request-forgery-csrf">Cross-site Request Forgery (CSRF)</a></li>
    <li><a href="#underprotected-apis">Underprotected APIs</a></li>
    <li><a href="#cryptographic-failures">Cryptographic Failures - OWASP A02:2021</a></li>
    <li><a href="#insecure-design">Insecure Design - OWASP A04:2021</a></li>
    <li><a href="#software-and-data-integrity-failures">Software and Data Integrity Failures - OWASP A08:2021</a></li>
    <li><a href="#server-side-request-forgery">Server-Side Request Forgery - OWASP A10:2021</a></li>
    <li><a href="#defense-in-depth">Defense In Depth</a></li>
    <li><a href="#stride-basics">STRIDE (Basics)</a></li>
    <li><a href="#secure-development-processes">Secure Development Processes</a></li>
  </ol>

&nbsp;

---

&nbsp;

## Injection

- <b>What is it?</b>
  - Untrusted user input is interpreted by server and executed
- <b>What is the impact?</b>
  - Data can be stolen, modified or deleted
- <b>How to prevent?</b>
  - Reject untrusted/ invalid input data
  - Use latest frameworks
  - Typically found by penetration testers/ secure code review

&nbsp;

---

&nbsp;

## Broken Authentication

- <b>What is it?</b>
  - Incorrectly build authentication and session management scheme that allows an attacker to impersonate another user
- <b>What is the impact?</b>
  - Attacker can take identity of victim
- <b>How to prevent?</b>
  - Don't develop your own authentication schemes
  - Use open source frameworks that are actively maintained by the community.
  - Use strong passwords
  - Require current credential when sensistive information is requested or changed
  - Multi-factor authentication (e.g. sms, password, fingerprint, iris scan etc.)
  - Log out or expire session after X amount of time
  - Be careful with 'remember me' functionality

![broken_authentication_example](/02-Broken%20Authentication/broken_authentication_example.png)

&nbsp;

---

&nbsp;

## Sensitive Data Exposure

- [OWASP - A3:2017-Sensitive Data Exposure](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure.html)
- <b>What is it?</b>
  - Sensitive data is exposed, e.g. social security numbers, passwords & health records
- <b>What is the impact?</b>
  - Data that are lost, exposed or corrupted can have severe impact on business continuity
- <b>How to prevent?</b>
  - Always obscure data (credit card numbers are almost always obscured)
  - Update cryptographic algorithm (MD5, DES, SHA-0 and SHA-1 are insecure)
  - Use salted encryption on storage of passwords
- What is the difference between encryption at rest an in transit?
  - Encryption at rest covers stored data, while encryption in transit covers data in flux (i.e. moving from one point to another point)

![sensitive_data_exposure_example](/03-Sensitive_Data_Exposure/sensitive_data_exposure_example.png)

&nbsp;

---

&nbsp;

## XML External Entities

- <b>What is it?</b>
  - Many older or poorly configured XML processors evaluate external entity references within XML documents
- <b>What is the impact?</b>
  - Extraction of data, remote code execution and denail of service attack
- <b>How to prevent?</b>
  - Use JSON, avoid avoiding serialization of sensitive data
  - Patch or upgrade all XML processors and libraries
  - Disable XXE and implement whitelisting
  - Detect, resolve and verify XXE with static application security testing tools

![xml_external_entities_example](/04-XML_External_Entities/xml_external_entities_example.png)

&nbsp;

---

&nbsp;

## Broken Access Control

- [OWASP - Broken Access Control](https://owasp.org/www-community/Broken_Access_Control)
- <b>What is it?</b>
  - Restrictions on what authenticated users are allowed to do are not properly enforced
- <b>What is the impact?</b>
  - Attackers can assess data, view sensitive files and modify data
- <b>How to prevent?</b>
  - Application should not solely rely on user input; check access rights on UI level and server level for requests to resources (e.g. data)
  - Deny access by default

&nbsp;

---

&nbsp;

## Security Misconfiguration

- [Troy Hunt - OWASP Top 10 for .NET developers part 6: Security Misconfiguration](https://www.troyhunt.com/owasp-top-10-for-net-developers-part-6/)
- <b>What is it?</b>
  - Human mistake of misconfigurating the system (e.g. providing a user with a default password)
- <b>What is the impact?</b>
  - Depends on the misconfiguration. Worst misconfiguration could result in loss of the system
- <b>How to prevent?</b>
  - Force change of default credentials
  - Least privilege: turn everything off by default (debugging, admin interface, etc.)
  - Static tools that scan code for default settings
  - Keep patching, updating and testing the system
  - Regularly audit system deployment in production
- <b>Catch exceptions: </b>How elegant does the system fail?
  - The expected behaviour of a query string (something we normally don't want a user manipulating)
  - The internal implementation of how a piece of untrusted data is handled (possible disclosure of weaknesses in the design)
  - Some very sensitive code structure details
  - The physical location of the file on the developers machine (further application structure disclosure)
  - Entire stack trace of the error (disclosure of internal events and methods)
  - Version of the .NET framework the app is executing on (discloses how the app may handle certain conf)

&nbsp;

---

&nbsp;

## Cross-Site Scripting (XSS)

- [OWASP - Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- <b>What is it?</b>
  - Untrusted user input is interpreted by browser and executed
- <b>What is the impact?</b>
  - Hijack user sessions, deface web sites, change content
- <b>How to prevent?</b>
  - Escape untrusted input data
  - Latest UI framework

&nbsp;

---

&nbsp;

## Insecure Deserialization

- <b>What is it?</b>
  - Error in translations between objects
- <b>What is the impact?</b>
  - Remote code execution, denial of service. Impact depends on type of data on that server
- <b>How to prevent?</b>
  - Validate user input
  - Implement digital signatures on serialized objects to enforce integrity
  - Restrict usage and monitor deserialization and log execeptions and failures

![deserialization](/08-Insecure%20Deserialization/deserialization.png)

&nbsp;

![insecure_deserialization_example](/08-Insecure%20Deserialization/insecure_deserialization_example.png)

&nbsp;

---

&nbsp;

## Using Components with Known Vulnerabilities

- [OWASP - A9:2017-Using Components with Known Vulnerabilities](https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities.html)
- [The Heartbleed Bug](http://heartbleed.com/)
- <b>What is it?</b>
  - Third-party components that the focal system uses (e.g. authentication frameworks)
- <b>What is the impact?</b>
  - Depending on the vulnerability it could range from subtle to seriously bad
- <b>How to prevent?</b>
  - Always stay current with third-party components
  - If possible, follow best practice of virtual patching

![using_components_with_known_vulnerabilities_example](/09-Using_Components_with_Known_Vulnerabilities/using_components_with_known_vulnerabilities_example.png)

&nbsp;

---

&nbsp;

## Insufficient Logging And Monitoring

- <b>What is it?</b>
  - Not able to witness or discover an attack when it happens or happened
- <b>What is the impact?</b>
  - Allows attacker to persist and tamper, extract, or destroy your data without you noticing it
- <b>How to prevent?</b>
  - Log login, access control and serer-side input validation failures
  - Ensure logs can be consumed easilu, but cannot be tampered with
  - Continuously improve monitoring and alerting process
  - Mitigate impact of breach: Rotate, Repave and Repair
    - <b>Rotate: </b>changes keys/ password frequently (multiple times a day)
    - <b>Repave: </b>restores the configuration to last good state (golden image)
    - <b>Repair: </b>patches vulnerability as soon as the patches are available

![insufficient_logging_and_monitoring_example](/10-Insufficient_Logging_And_Monitoring/insufficient_logging_and_monitoring_example.png)

&nbsp;

---

&nbsp;

## Insufficient Attack Protection

- [OWASP - Attack Surface Analysis Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)
- [OWASP - Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- <b>What is it?</b>
  - Applications that are attacked but do not recognize it as an attack, lettting the attacker attack again and again
- <b>What is the impact?</b>
  - Leak of data, decrease application availability
- <b>How to prevent?</b>
  - Detect and log normal and abnormal use of application
  - Respond by automatically blocking abnormal users or range of IP addresses
  - Patch abnormal use quickly

![insufficient_attack_protection_example](/11-Insufficient_Attack_Protection/insufficient_attack_protection_example.png)

&nbsp;

---

&nbsp;

## Cross-site request forgery (CSRF)

- <b>What is it?</b>
  - An attack that forces a victim to execute unwanted actions on a web application in which they're currently authenticated
- <b>What is the impact?</b>
  - Victim unknowingly executes transactions
- <b>How to prevent?</b>
  - Reauthenticate for all critical actions (e.g. transfer money)
  - Include hidden token in request
  - Most web frameworks have built-in CSRF protection, but isn't enabled by default

![cross-site%20request%20forgery_example](/12-cross_site_request_forgery/cross-site%20request%20forgery_example.png)

&nbsp;

---

&nbsp;

## Underprotected APIs

- [OWASP - Source Code Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- [REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- <b>What is it?</b>
  - Applications expose rich connectivity options through APIs, in the browser to a user. These APIs are often unprotected and contain numerous vulnerabilities.
- <b>What is the impact?</b>
  - Data theft, corruption, unauthorized access, etc.
- <b>How to prevent?</b>
  - Ensure secure communication between client browser and server API
  - Reject untrusted/ invalid input data
  - Use latest framework
  - Vulnerabilities are typically found by penetration testers and secure code reviewers

![underprotected_apis_example](/13-Underprotected_APIs/underprotected_apis_example.png)

&nbsp;

---

&nbsp;

## Cryptographic Failures

- <b>What is it?</b>
  - Ineffective execution & configuration of cryptography (e.g. FTP, HTTTP, MD5, WEP)
- <b>What is the impact?</b>
  - Sensitive data exposure
- <b>How to prevent?</b>
  - Never roll your own crypto! Use well-known open source libraries
  - Static code analysis tools can discover this issue
  - Key management (creation, destruction, distribution, storage and use)

&nbsp;

---

&nbsp;

## Insecure Design

- <b>What is it?</b>
  - A failure to use security by design methods/ principles resulting in a weak or insecure design
- <b>What is the impact?</b>
  - Breach of confidentiality, integrity and availability
- <b>How to prevent?</b>
  - Secure lifecycle (embed security in each phase; requirements, design, development, test, deployment, maintenance and decommissioning)
  - Use manual (e.g. code review, threat modelling) and automated (e.g. SAST and DAST) methods to improve security

![insecure_design_example](/15-Insecure_Design/insecure_design_example.png)

&nbsp;

---

&nbsp;

## Software and Data Integrity Failures

- <b>What is it?</b>
  - E.g. an application that relies on updates from a trusted exernal source, however the update mechanism is compromised
- <b>What is the impact?</b>
  - Supply chain attack; data exfiltration, ransomwawre, etc
- <b>How to prevent?</b>
  - Verify input (in this case software updates with digital signatures)
  - Continuously check for vulnerabilities in dependencies
  - Use Software Bill of Materials
  - Unconnected back ups

&nbsp;

---

&nbsp;

## Server-Side Request Forgery

- <b>What is it?</b>
  - Misuse of prior established trust to accesss other resources. A web application is fetching a remote resource without validating the user-supplied URL
- <b>What is the impact?</b>
  - Scan and connect to internal services. In some cases the attacker could access sensitive data
- <b>How to prevent?</b>
  - Sanitize and validate all client-supplied input data
  - Segment remote server access functionality in separate networks to reduce the impact
  - Limiting connections to specific ports only (e.g. 443 for https)

![server_side_request_forgery_example](/17-Server_Side_Request_Forgery/server_side_request_forgery_example.png)

&nbsp;

---

&nbsp;

## Defense In Depth

![defense_in_depth](/18-Defense_In_Depth/defense_in_depth.png)

- Defense in Depth is commonly refered to as the "castle approach" because it mirrors the layered defenses of a medieval castle. Before you can penetrate a castle you are faced with the moat, ramparts, draw-bridge, towers, battlements and so on.
- Multi-layered approach with intentional redundancies increases the security of a system as a whole and addresses many different attack vectors.

&nbsp;

---

&nbsp;

## STRIDE (Basics)

- <b>Why?</b>
  - Examine what can go wrong
  - What are you going to do about it
  - Determine whether you are doing a good job
- <b>STRIDE</b>
  - Spoofing
  - Tampering
  - Repudiation
  - Information disclosure
  - Denial of service
  - Elevation of privilege
- [STRIDE, CIA and the Modern Adversary](https://docs.microsoft.com/en-us/archive/blogs/heinrichg/stride-cia-and-the-modern-adversary)
- [The STRIDE Threat Model](https://docs.microsoft.com/en-us/previous-versions/commerce-server/ee823878%28v%3Dcs.20%29)
- [Chapter 3 – Threat Modeling](<https://docs.microsoft.com/en-us/previous-versions/msp-n-p/ff648644(v=pandp.10)?redirectedfrom=MSDN>)

&nbsp;

---

&nbsp;

## Secure Development Processes

![sdlc_ms_sdl](/20-Secure_Development_Processes/sdlc_ms_sdl.png)

- Other secure development processes are:
  - Software Assurance Maturity Model (previous called CLASP)
  - Touchpoints for software security
- [Microsoft SDL Resources](https://www.microsoft.com/en-us/securityengineering/sdl/resources)
- [OpenSAMM](https://www.opensamm.org/download/)
- [Security Headers](https://securityheaders.com/)
- [Qualys SSL Labs](https://www.ssllabs.com/)
- [IP Leak](https://ipleak.net/)

&nbsp;

---

&nbsp;
