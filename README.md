<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#about-the-project">About The Project</a></li>
    <li><a href="#application-security-introduction">Application Security Introduction</a></li>
      <ol>
        <li><a href="#resources">Resources</a></li>
        <li><a href="#owasp-vs-sans">OWASP VS SANS</a></li>
        <li><a href="#definitions">Definitions</a></li>
        <li><a href="#cve-cvss--cwe">CVE, CVSS & CWE</a></li>
        <li><a href="#api-security">API Security</a></li>
        <li><a href="#owasp-top-ten-additional-notes">OWASP Top Ten (Additional Notes)</a></li>
      </ol>
  </ol>
</details>

&nbsp;

## About The Project

- Application Security - The Complete Guide
- Developing security in the Software Development Life Cycle (SDLC)
- [Securely Built](https://securelybuilt.com/)

&nbsp;

---

&nbsp;

## Application Security Introduction

![sdlc](/diagrams/sdlc.png)

- **Requirements Analysis**
  - High level view of requirements and goals
  - Extracts requirements or requirements analysis
  - Clients have an idea of what they what - not how
  - Scope defined and agreed with
  - Prioritization of requirements
  - Slotting of resources
- **Designing**
  - Describe features and operations
    - Screen layout
    - Business rules
    - Process diagrams
    - Pseudo code and documentation
  - Prototype work
  - Detailed design
    - Technology choices
    - System architecture
- **Implementation**
  - **Input**
    - Requirements
    - Business Process
    - Business Rules
    - Software Design
    - Specifiction
  - **Output**
    - Deliverable Code
- **Testing**
  - Static Analysis: Code testing
  - Dynamic Analysis: Running software testing
  - Unit testing: Verify the functionality of specific code
  - Integration testing: Verify the interfaces between components
  - Interface testing: Testing data passed between units
  - System testing: Testing a completely integrated system
- Evolution
  - Patch
  - Build
  - Test
  - Prod

&nbsp;

---

&nbsp;

- Security is anything you do to protect an **asset** that is vulnerable to some **attack**, **failure**, or **error**
  - An **asset** is anything you deem to have **value**
    - Holds its value
    - Produces value
    - Provides access to value
- A vulnerability is any weakness in an asset that makes it susceptible to attack or failure
- An attack is any **intentional** action that can reduce the value of an asset
- Failures and errors are **unintentional** actions that can reduce the value of an asset
- Attacks, failures, and errors are actions that we collectively refer to as **threats**
- Thus: Security is anything you do to protect an asset that is **vulnerable** to some **threat**

&nbsp;

---

&nbsp;

- The "Anything" Security Goals
  - Security, and more specifically Cybersecurity, can be understood as a set of goals
  - These goals are specifically defined by how we measure an asset's value
  - How does value define our security goals?
  - The goal of security is to protect an asset's **value** from threats
- **Steps**:
  1. Determining what assets we want to protect
  2. Learn how the asset works and interacts with other things
  3. Determine how our asset's value is reduced directly and indirectly
  4. Take steps to mitigate the threats
- We must consider the unique nature of it assets and capabilities when considering security goals
- **CIA**
  - **Confidentiality:** Information is only available to those who should have access
    - When we protect something that provides access value we are maintaining its confidentiality
  - **Integrity:** Data is known to be correct and trusted
    - When we protect something that produces value we are maintaining its availability
  - **Availability:** Information is available for use by legitimate users when it is needed
- [The Protection of Information in Computer Systems](https://web.mit.edu/Saltzer/www/publications/protection/)
- We have well defined goals and security mechanisms, but some mechanisms are better because they fit security principles
  - Security principles aid in selecting or designing the correct mechanisms to implement our goals
    1. **Economy of Mechanism:** Keep things simple so that it is easier to defend
    2. **Fail-Safe Defaults**
    3. **Complete Mediation:** Check every access to the resource for authorization and authority
    4. **Open Design:** There's no security through obscurity
    5. **Separation of Privilege:** Two keys are more secure than one. And you want to make sure that certain activities in certain business, certain business functions within the application or system require especially sensitive ones, require more than one person to perform that activity
    6. **Least Privilege:** Only have access to just what you need to do your job and no more
    7. **Least Common Mechanism:** The least common mechanism means reducing the shared components and systems, since it provides the opportunity for information leaked or inappropriate access
    8. **Psychological Acceptability:** The system needs to be designed so that people do not attempt to circumvent the security
    9. **Work Factor:** The cost of the cost of circumventing the security should exceed the asset. For example, we want to make sure that in order to break encryption that it requires a lot of cost to the attacker that is more expensive that what the actual gain would be
    10. **Compromise Recording:** Audit everything

```
                                                 *
                                               *   *
                                              *      *
                                             *  Goals  *          -> C.I.A
                                            *************
                                           *  Principles  *       -> Point 1 to 10
                                          ******************
                                         *     Mechanisms    *    -> What this course is about
                                        ************************
```

&nbsp;

---

&nbsp;

### Resources

- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://owasp.org/www-project-cheat-sheets/)
- [OWASP Projects](https://owasp.org/projects/)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [OWASP Zed Attack Proxy (ZAP)](https://www.zaproxy.org/)
- [OWASP OWTF](https://owasp.org/www-project-owtf/)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Secure Coding Practices-Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/migrated_content)
- [OWASP Java HTML Sanitizer](https://owasp.org/www-project-java-html-sanitizer/)
- [OWASP CSRFGuard](https://owasp.org/www-project-csrfguard/)
- [OWASP Enterprise Security API (ESAPI)](https://owasp.org/www-project-enterprise-security-api/)
- [OWASP Security Knowledge Framework](https://owasp.org/www-project-security-knowledge-framework/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
- [OWASP Defectdojo](https://owasp.org/www-project-defectdojo/)
- [CWE/SANS TOP 25 Most Dangerous Software Errors](https://www.sans.org/top25-software-errors/)
- [OWASP API Security Top 10 cheat sheet](https://apisecurity.io/encyclopedia/content/owasp/owasp-api-security-top-10-cheat-sheet.htm)

&nbsp;

---

&nbsp;

### OWASP VS SANS

- In developing their Top 25 list, CWE/SANS included a comparision to the OWASP Top Ten making a clear statement of the importance of OWASP's list while also recognizing distinct differences between the two
- Most clearly defined is that the OWASP Top Ten deals strictly with vulnerabilities found in web applications where the Top 25 deals with weaknesses found in desktop and server applications as well
- A further contrast is seen in how the list is compiled. OWASP giving more credence to the risk each vulnerability presents as opposed to the CWE/SANS Top 25 that included the prevalence of each weakness.
- This factor is what gives Cross-site scripting the edge in the Top 25 as it is ranked number 1 while OWASP has it ranked at number 2

&nbsp;

---

&nbsp;

### Definitions

- **Confidentiality:** Concept of preventing the disclosure of information to unauthorized parties
- **Integrity:** Refers to protecting the data from unauthorized alteration
- **Availability:** Access to systems by authorized personnel can be expressed as the system's availability
- **Authentiction:** Authentication is the process of determining the identity of a user
- **Authorization:** Authorization is the process of applying access control rules to a user process, determining whether or not a particular user process can access an object
- **Accounting (Audit):** Accounting is a means of measuring activity.
- **Non-Repudiation:** Non-repudiation is the concept of preventing a subject from denying a previous action with an object in a system
- **Least Privilege:** Subject should have only the necessary rights and privileges to perform its current task with no additional rights and privileges
- **Separation of Duties:** Ensures that for any given task, more than one individual needs to be involved
- **Defense in Depth:** Defense in depth is also known by the terms layered security and diversity defense
- **Fail Safe:** When a system experiences a failure, it should fail to a safe state. (Doors open when there is a power failure)
- **Fail Secure:** The default state is locked or secured. So a fail secure lock locks the door when power is removed
- **Single point of failure:** A single point of failure is any aspect of a system that, if it fails, the entire system fails
- **Threat Actors**
  - Script Kiddie
  - Insider
  - Hacktivist & Terrorist
  - Cybercriminal
  - Advanced Persistent Threat

&nbsp;

---

&nbsp;

### CVE, CVSS & CWE

- **Common Vulnerabilities and Exposure (CVE)** is a list of common identifiers for publicly known cyber security vulnerabilities
  - One identifier for one vulnerability with one standardized description
  - A dictionary rather than a database
  - The way to interoperability and better security coverage
  - A basis for evaluation among services, tools, and databases
  - Industry-endorse via the CVE Numbering Authorities, CVE Board, and numerous products and services that include CV
  - [CVE List Home](https://cve.mitre.org/cve/)
- **Common Vulnerability Scoring System (CVSS)** provides a way to capture the principal characteristics os a vulnerability and produce a numberical score reflecting its severity. The numerical score can then be translated into a qualitative representation (such as low, medium, high, and critical) to help organiations properly assess and prioritize their vulnerability management processes
  - [National Vulnerability Database](https://nvd.nist.gov/vuln-metrics/cvss)
- **Common Weakness Enumeration (CWE)** is a community-developed list of common software security weaknesses. It serves as a common language, a measuring stick for software security tools, and as a baseline for weakness identification, mitigation, and prevention efforts
  - At is core, CWE is a list of software weaknesses types
  - Three types:
    - **Research:** This view is intended to facilitate research into weaknesses, including their inter-dependencies and their role in vulnerabilities
    - **Development:** This view organizes weaknesses aroun concepts that are frequently used or encountered in software development
    - **Architecture:** This view organizes weaknesses according to common architectural security tactics
  - [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/)

![defense-in-depth-example](/diagrams/defense-in-depth-example.png)

- "**Defense In Depth** is an approach to cybersecurity in which a series of defensive mechanisms are layered in order to protect valuable data and information. If one mechanism fails, another steps up immediately to thwart an attack." -ForcePoint
  - Don't rely on Defense In Depth to always protect your app
  - Systems fail, they can be circumvented by the weakest link
  - Your app may not always be behind those defenses

![proxy-tools](/diagrams/proxy-tools.png)

- [Charles](https://www.charlesproxy.com/)
- [Telerik Fiddler](https://www.telerik.com/fiddler)
- Browser "Developer Tools"

&nbsp;

---

&nbsp;

### OWASP Top Ten (Additional Notes)

- **A01 Broken Access Control**
  - **Authentication** is providing and validating identity.
  - **Authorization** includes the execution rules that determines what functionality and data the user (or Principal) may access, ensuring the proper allocation of access rights after authentication is successful.
  - **Access Control**
    - Enforces policy such that users cannot act outside of their intended permissions
    - Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside of the limits of the user.
    - Weaknesses are common due to the lack of automated detection, and lack of effective functional testing by application developers.
    - The technical impact is attackers acting as users or administrators, or users using privileged funcitons, or creeating, accessing, updating or deleting every record.
- **A02 Cryptographic Failures**
  - **Data Protection**
    - **Protected Health Information (PHI)**
      - Names, dates, phone/ fax numbers, email, SSN, MRN, account numbers, biometric (finger, retinal, voice prints) & images
    - **Personally Identifiable Information (PII)**
      - Name, address, passport, vehicle information, drivers license, credit card numbers, digital identity, birthplace, genetic information and login name
    - **Sensitive Financial Infnormation**
      - Credit/ Debit card numbers and security codes, account numbers, loan agreements, loan details, tax ID & PoS tansactions
- **A03 Injection**
  - **Other Injection Flaws**
    - **OS Command**
    - **LDAP**
    - **XPATH**
- **A04 Insecure Design**
  - **Bad Bots**
    - A retail chain's e-commerce website does not have protection against bots run by scalpers buying high-end video cards to resell auction websites. This creates terrible publicity for the video card makers and retails chain owners and enduring bad blood with enthusiasts who cannot obtain these cards at any price. Careful anti-bot design and domain logic rules, such as purchases made within a few seconds of availability, might identify inauthentic purchases and rejected such transactions.
- **A05 Security Misconfiguration**
  - Absence of security settings in:
    - Application
    - Framework
    - Database
    - Web server
    - Platform
  - Default settings in the cloud
  - A cloud service provider (CSP) has default sharing permissions open to the Internet by other CSP users. This allows sensitive data stored within cloud storage to be accessed.
- **A06 Vulnerable and Outdated Components**
  - Most applicaions include either commercial products or Open Source Software(OSS) within their software bundles.
    - Find a solution like **Dependency Check**, GitLab, or Jfrog Xray, to automatically scan for vulnerable packages.
  - For commercial products, most major vendors such as Oracle, Google and IBM provide **Security Bulletins to distribution lists** for notification purposes. Make sure you are signed up for these services.
    - [Sign-up](https://nvd.nist.gov/general/email-list) for regular security bullets from the National Vulnerability Database and regularly monitor components for security issues and updated versions.
  - **Notification**
    - Have means for receiving notifications on ptentially vulnerable software.
    - Many vendors like Microsoft already offer a notification service, however other services or feeds exist.
    - Receiving notification is only part of the solution. You must also be able to:
      - Know where to patch (what systems or software arre vulnerable)
      - Have the ability to test the new patch
      - Have a means to deliver the patch
      - Ability to notify those impacted by the changes to teh system (users, customers, etc)
  - **Patching Process**
    - Development -> Pre Prod -> Production
    - Testing conducted at Development and Pre Prod
- **A07 Identification and Authentication Failures**
  - Attacks:
    - Password guessing attack (social engineering)
      - John from IT, needs your help
    - Dictionary attack
      - Dictionary words that are hased and tests
    - Brute force attack
      - Guessing or targeted hashes
    - Username enumeration
      - Guessable patterns of usernames or log in failure messages that reveal too much
    - Phishing
      - Trick users into providing their credentials to an imposter, look-alike site
  - Account Recovery Risks:
    - Social engineering
      - Emailing a password reset form without using something like two factor
    - Easily guessable security answers
      - Answers that can be easily found online
      - "What school did you attend?"
    - Password sent through insecure channels
      - Email
    - Password change not required
      - Once you've been given a new password, it should be changed on the next login
- **A08 Software and Data Integrity Failures**
  - **Case Study:** [NPR - A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
- **A09 Security Logging and Monitoring Failures**
  - Security Information and Event Management (SIEM)

![siem-solution-purplesec](/diagrams/siem-solution-purplesec.png)

- **A10 Server-Side Request Forgery (SSRF)**

![ssrf-occurs-when-we-do-not](/diagrams/ssrf-occurs-when-we-do-not.png)

&nbsp;

---

&nbsp;
