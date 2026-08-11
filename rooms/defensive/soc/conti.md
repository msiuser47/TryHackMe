conti description :
Conti
An Exchange server was compromised with ransomware. Use Splunk to investigate how the attackers compromised the server.


45 min

١٤٬٥٠٢

User profile photo.
User profile photo.
Share your achievement

Start AttackBox


Save Room

330 Recommend

Connectivity
Options
Room completed: 100%
 Chart Scoreboard Write-ups Video
Score updated

Task 1
SITREP

Task 2
Exchange Server Compromised
Set up your virtual environment
To successfully complete this room, you'll need to set up your virtual environment. This involves starting both your AttackBox (if you're not using your VPN) and Lab Machines, ensuring you're equipped with the necessary tools and access to tackle the challenges ahead.

Attacker machineMachine info
Status:
Off

Start AttackBox

Lab machineMachine info
Status:
Off

Start Lab Machine
Below are the error messages that the Exchange admin and employees see when they try to access anything related to Exchange or Outlook.

Exchange Control Panel:


Outlook Web Access:



Task: You are assigned to investigate this situation. Use Splunk to answer the questions below regarding the Conti ransomware. 

Answer the questions below
Can you identify the location of the ransomware?
C:\Users\Administrator\Documents\cmd.exe

Correct Answer

What is the Sysmon event ID for the related file creation event?

11

Correct Answer
Can you find the MD5 hash of the ransomware?

290c7dfb01e50cea9e19da81a781af2c

Correct Answer
What file was saved to multiple folder locations?

readme.txt

Correct Answer
What was the command the attacker used to add a new user to the compromised system?

net user /add securityninja hardToHack123$

Correct Answer
The attacker migrated the process for better persistence. What is the migrated process image (executable), and what is the original process image (executable) when the attacker got on the system?

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,C:\Windows\System32\wbem\unsecapp.exe

Correct Answer

The attacker also retrieved the system hashes. What is the process image used for getting the system hashes?

C:\Windows\System32\lsass.exe

Correct Answer

What is the web shell the exploit deployed to the system?

i3gfPctK1c2x.aspx

Correct Answer

What is the command line that executed this web shell?

attrib.exe  -r \\\\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx

Correct Answer

What three CVEs did this exploit leverage? Provide the answer in ascending order.

CVE-2018-13374,CVE-2018-13379,CVE-2020-0796

Correct Answer

solve :
TryHackMe: Conti Ransomware Room Walkthrough
Eva Monica Mijares
Eva Monica Mijares

Follow
4 min read
·
Mar 16, 2023
11




The Splunk platform helps IT and security teams to ensure their organizations are secure, strong and keeping up on the advancement of technology, and likewise the cybercriminals. In this Conti Ransomware room, we identify ransomware on Splunk logs.

Scenario:

Some employees from your company reported that they can’t log into Outlook. The Exchange system admin also reported that he can’t log in to the Exchange Admin Center. After initial triage, they discovered some weird readme files settled on the Exchange server. Below is a copy of the ransomware note.

You are assigned to investigate this situation. Use Splunk to answer the questions below regarding the Conti ransomware.

Question 1: Can you identify the location of the ransomware?

Answer: c:\Users\Administrator\Documents\cmd.exe

Step 1: Based on question 2, have determined that this is a file create event, so we find out in the below article event ID used to filter this type of event.

https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

We search the EventCode=11 on the search field and hit All Time on the drop down on the upper left, then click on image on interesting fields section. Looking at it we can see highlighted section- cmd.exe executable is stored in a strange location.

Press enter or click to view image in full size

Question 2: What is the Sysmon event ID for the related file creation event?

Answer: 11

Step 2: Basically, the answer is given on Step 1.

Question 3: Can you find the MD5 hash of the ransomware?

Answer: 290C7DFB01E50CEA9E19DA81A781AF2C

Step 3: To identify this, click on the image file cmd.exe as seen in Step1 and simply remove the event ID filter, then add MD5. We can see a single event returned, and highlighted on the snapshot is the MD5 hash.

Press enter or click to view image in full size

Question 4: What file was saved to multiple folder locations?

Answer: readme.txt

Step 4: Search this filter “Image=”c:\\Users\\Administrator\\Documents\\cmd.exe” EventCode=11”, and after that click on TargetFileName on the interesting fields section, we can see below result.

Press enter or click to view image in full size

Question 5: What was the command the attacker used to add a new user to the compromised system?

Get Eva Monica Mijares’s stories in your inbox
Join Medium for free to get updates from this writer.

Enter your email
Subscribe

Remember me for faster sign in

Answer: net user /add securityninja hardToHack123$

Step 5: Filter out using CommandLine and wildcard on add to check all commands containing add. Below is the result command.

Press enter or click to view image in full size

Question 6: The attacker migrated the process for better persistence. What is the migrated process image (executable), and what is the original process image (executable) when the attacker got on the system?

Answer: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,C:\Windows\System32\wbem\unsecapp.exe

Step 6: We can use Sysmon Event ID 8 Create Remote Thread, which detects when a process creates a thread in another process. In the interesting fields section, click on TargetImage and it will show two events, click on the second one and you will find source and target locations as below snapshot.

Press enter or click to view image in full size

Question 7: The attacker also retrieved the system hashes. What is the process image used for getting the system hashes?

Answer: C:\\Windows\\System32\\lsass.exe

Step 7: Using the EventCode=8 filter alone, check the TargetImage and it will show two events, if we refer to the output from the search used in question 6, we can see that a second process migration takes place between unsecapp.exe and lsass.exe

Press enter or click to view image in full size

Question 8: What is the web shell the exploit deployed to the system?

Answer: i3gfPctK1c2x.aspx

Step 8: We get a hint for this one, so we filtered IIS events for POST requests and common web shell file types like .aspx, used the wildcard *.aspx*. Then, under the “cs_uri_stem” in the interesting field, a suspicious looking filename with a “.aspx” file extension is seen, see below snapshot.



Question 9: What is the command line that executed this web shell?

Answer: attrib.exe -r \\\\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx

Step 9: Filtered for the .aspx web shell “i3gfPctK1c2x.aspx” in search field and added commandline filter as well, it returned one event. Click the event to view and find the full commandline, see snapshot for reference.


Press enter or click to view image in full size

Question 10: What three CVEs did this exploit leverage?

Answer: CVE-2020–0796,CVE-2018–13374,CVE-2018–13379

Step 10: We get a hint where external research is required. This article contains a number of CVE’s related to Conti Ransomware. https://cybersecurityworks.com/blog/ransomware/is-conti-ransomware-on-a-roll.html