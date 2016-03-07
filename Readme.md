##### Incident Response Triage:
Scripted collection of system information. (Must be "Run As ADMINISTRATOR"!)
Original source was [Triage-ir](https://code.google.com/p/triage-ir/) a script written by Michael Ahrendt.
Unfortunately Michael's last changes were [posted](http://mikeahrendt.blogspot.ca/2012/01/automated-triage-utility.html) on 9th November 2012

I let Michael [know](http://mikeahrendt.blogspot.com/2012/01/automated-triage-utility.html?showComment=1455628200788#c6111030418808145121) that I have forked his project:
I am pleased to anounce that he gave me his blessing, long live Open Source!)

###### What if having a full disk image is not an option during an incident?
Imagine that you are investigating a dozen or more possibly infected or compromised systems.
Can you spend 2-8 hours making a forensic copy of the hard drives on those computers?
In such situation fast forensics\"Triage" is the solution for such a situation.
Instead of copying everything, collecting some key files can solve this issue.

IRTriage will collect:
- system information
- network information
- registry hives
- disk information, and
- dump memory.

One of the powerful capabilities of IRTriage is collecting information from Volume Shadow Copy which can defeat many anti-forensics techniques.

The IRTriage is itself just an autoit script that depend on other tools such as:
- FDpro *
- Sysinternals Suite
- Regripper
- md5deep
- 7zip
- and some windows built-in commands.

In case of an incident, you want to make minimal changes to the "evidence machine",
therefore I would suggest to copy it to USB drive, only issue here is if you are planning to dump the memory, the USB drive must be larger than the physical ram.

Once you launch the application you can select which information you would like to collect.
Each category is in a separate tab.
All the collected information will be dumped into a new folder labled with date-time and the hostname.

NEWS:
I have since fixed the "commands executed" logging errors and updated the project to currently available tools.
I have commented out Moonsol's memory acquisition software in favor of HBGary's FDpro.
   -If you are unable to get HBGary's FDpro it is easy to switch back to Moonsol's memory acquisition software;)

As of version 2016.02.24 IRTriage is now truly compatible with the following versions of Windows:
   - Windows Workstations "WIN_10", "WIN_81", "WIN_8", "WIN_7", "WIN_VISTA", "WIN_XP", "WIN_XPe",
   - Windows Servers: "WIN_2016", "WIN_2012R2", "WIN_2012", "WIN_2008R2", "WIN_2008", "WIN_2003".

As of version 2016.02.26 I have started to add new funtions:

	*Processes
		- tcpvcon -anc -accepteula > Process2PortMap.csv
		- tasklist /SVC /FO CSV > Processe2exeMap.csv
		- wmic /output:ProcessesCmd.csv process get Caption,Commandline,Processid,ParentProcessId,SessionId /format:csv

	*SystemInfo
		- wmic /output:InstallList.csv product get /format:csv
		- wmic /output:InstallHotfix.csv qfe get caption,csname,description,hotfixid,installedby,installedon /format:csv

Future Updates\Features will be based on this report: [On-scene_Triage_open_source_forensic_tool_chests_Are_they_effective](http://www.researchgate.net/profile/Stavros_Shiaeles/publication/236681282_On-scene_Triage_open_source_forensic_tool_chests_Are_they_effective/links/00b4953ac91d0d0086000000.pdf?inViewer=true&pdfJsDownload=true&disableCoverPage=true&origin=publication_detail)

I have finally compiled my own personalized version of ReactOS's "cmd.exe", 
it can now use Linux equivalent commands:

    ls = dir
    cp = copy
    rm = delete
    ln = mklink

Just to name a few.

Next step is to integrate [Didier Stevens](http://blog.didierstevens.com/2015/12/13/windows-backup-privilege-cmd-exe/)'s new commands: privilege and info. Both commands would be invaluable for a Forensic Analyst. I hope he is willing to help me integrate his mods into the latest version of ReactOS's "cmd.exe", so far I have failed any attempts;-(

