Incident Response Triage: Scripted collection of system information. (Must be "Run As ADMINISTRATOR"!)  
Original source was Triage-ir a script written by Michael Ahrendt https://code.google.com/p/triage-ir/ 
Unfortunately Michael's last changes were posted on 9th November 2012
http://mikeahrendt.blogspot.ca/2012/01/automated-triage-utility.html

I have since fixed the "commands executed" logging errors and updated the project to currently available tools.
I have commented out Moonsol's memory acquisition software in favor of HBGary's FDpro.

What if having a full disk image is not an option during an incident?
Imagine that you are investigating a dozen or more possibly infected or compromised systems. 
Can you spend 2-8 hours making a forensic copy of the hard drives on those computers? 
In such situation fast forensics\"Triage" is the solution for such a situation. 
Instead of copying everything, collecting some key files can solve this issue.

IRTriage will collect: 
-system information
-network information
-registry hives
-disk information, and 
-dump memory. 

One of the powerful capabilities of IRTriage is collecting information from Volume Shadow Copy which can defeat many anti-forensics techniques.

The IRTriage is itself just an autoit script that depend on other tools such as: 
-FDpro,
-Sysinternals Suite 
-Regripper
-md5deep
-7zip
and some windows built-in commands.

In case of an incident, you want to make minimal changes to the "evidence machine", 
therefore I would suggest to copy it to USB drive, only issue here is if you are planning to dump the memory, the USB drive must be larger than the physical ram.

Once you launch the application you can select which information you would like to collect. 
Each category is in a separate tab. 
All the collected information will be dumped into a new folder labled with date-time and the hostname.

http://www.researchgate.net/profile/Stavros_Shiaeles/publication/236681282_On-scene_Triage_open_source_forensic_tool_chests_Are_they_effective/links/00b4953ac91d0d0086000000.pdf?inViewer=true&pdfJsDownload=true&disableCoverPage=true&origin=publication_detail
