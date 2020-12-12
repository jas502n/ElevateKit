升降套件
========= <>
Elevate Kit演示了如何使用第三方特权升级攻击
带有钴击的信标有效载荷。

Elevate Kit适用于Cobalt Strike 3.6及更高版本。
https://www.cobaltstrike.com/

有关Aggressor脚本的信息，请访问：
https://www.cobaltstrike.com/aggressor-script/

演示视频：
https://www.youtube.com/watch?v=sNKQVchyHDI

如何使用
======== <>
1.下载此存储库
git clone https://github.com/rsmudge/ElevateKit.git

2.将elevate.cna加载到钴击中。
-转到Cobalt Strike->脚本，按Load，选择elevate.cna

3.与信标互动

4. Elevate Kit注册电梯和特权升级漏洞。

   电梯在高架环境中运行命令。输入“ runasadmin”
   查看可用特权电梯列表。

   漏洞利用会在提升的环境中生成有效负载。输入“提升”为
   查看可用特权升级攻击的列表。

5.键入“ elevate <攻击名称>”以在提升的上下文中生成会话。

   使用'runasadmin <elevator> <command>'在提升的环境中运行命令
   上下文。

许可证（elevate.cna）
===== <>
版权所有：2016，Strategy Cyber​​ LLC
许可证：BSD-3条款

模组
===== <>
包含的DLL和.ps1文件是由其他作者开发的

cve-2020-0796：SMBv3压缩缓冲区溢出（SMBGhost）（CVE 2020-0796）
https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/CVE-2020-0796
https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/cve_2020_0796_smbghost.rb

作者：DanielGarcíaGutiérrez，Manuel BlancoParajón，Spencer McIntyre
许可证：Metasploit许可证（BSD）

ms14-058：TrackPopupMenu Win32k NULL指针解除引用（CVE-2014-4113）
https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/cve-2014-4113
https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms14_058_track_popup_menu.rb

作者：未知，胡安·瓦兹克斯（Juan Vazquez），斯宾塞·麦金太尔（Spencer McIntyre），OJ Reeves
许可证：BSD 3-Clause

ms15-051：Windows ClientCopyImage Win32k漏洞（CVE 2015-1701）
https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/cve-2015-1701
https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms15_051_client_copy_image.rb

作者：未知，hfirefox，OJ Reeves，Spencer McIntyre
许可证：BSD 3-Clause

ms16-016：WebDav本地特权升级（CVE 2016-0051）
https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/cve-2016-0051/dll
https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms16_016_webdav.rb

作者：Tamas Koczka和William Webb
许可证：BSD 3-条款

ms16-032：二级登录句柄特权升级（CVE-2016-099）
https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-MS16032.ps1

作者：Ruben Boonen（@FuzzySec）
许可证：BSD 3-Clause

uac-eventvwr：使用eventvwr.exe绕过UAC
https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-EventVwrBypass.ps1

作者：Matt Nelson（@ enigma0x3）
许可证：BSD 3-Clause

uac-schtasks：使用schtasks.exe绕过UAC（通过SilentCleanup）
https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-EnvBypass.ps1

作者：Petr Medonos（@PetrMedonos）
许可证：BSD 3-Clause

uac-wscript：使用wscript.exe绕过UAC
https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-WScriptBypassUAC.ps1

作者：@ enigma0x3，@ harmj0y，Vozzie
许可证：BSD 3-Clause






Elevate Kit
=========<>
The Elevate Kit demonstrates how to use third-party privilege escalation attacks
with Cobalt Strike's Beacon payload.

Elevate Kit is for Cobalt Strike 3.6 and later. 
https://www.cobaltstrike.com/

Information on Aggressor Script is at: 
https://www.cobaltstrike.com/aggressor-script/

Demonstration video: 
https://www.youtube.com/watch?v=sNKQVchyHDI

How to use
========<>
1. Download this repository
	git clone https://github.com/rsmudge/ElevateKit.git

2. Load elevate.cna into Cobalt Strike. 
	- Go to Cobalt Strike -> Scripts, press Load, select elevate.cna

3. Interact with a Beacon

4. The Elevate Kit registers elevators AND privilege escalation exploits.

   An elevator runs a command in an elevated context. Type 'runasadmin' to
   see a list of available privilege elevators.

   An exploit spawns a payload in an elevated context. Type 'elevate' to
   see a list of available privilege escalation attacks.

5. Type 'elevate <exploit name>' to spawn a session in an elevated context.

   Use 'runasadmin <elevator> <command>' to run a command in an elevated
   context.

License (elevate.cna)
=====<>
Copyright: 2016, Strategic Cyber LLC
License: BSD-3-clause

Modules
=====<>
The included DLL and .ps1 files are developed by other authors 

cve-2020-0796: SMBv3 Compression Buffer Overflow (SMBGhost) (CVE 2020-0796)
https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/CVE-2020-0796
https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/cve_2020_0796_smbghost.rb

	Author: Daniel García Gutiérrez, Manuel Blanco Parajón, Spencer McIntyre
	License: Metasploit License (BSD)

ms14-058: TrackPopupMenu Win32k NULL Pointer Dereference (CVE-2014-4113)
https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/cve-2014-4113
https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms14_058_track_popup_menu.rb

	Author: Unknown, Juan Vazquez, Spencer McIntyre, OJ Reeves
	License: BSD 3-Clause

ms15-051: Windows ClientCopyImage Win32k Exploit (CVE 2015-1701)
https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/cve-2015-1701
https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms15_051_client_copy_image.rb

	Author: Unknown, hfirefox, OJ Reeves, Spencer McIntyre
	License: BSD 3-Clause

ms16-016: WebDav Local Privilege Escalation (CVE 2016-0051)
https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/cve-2016-0051/dll
https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms16_016_webdav.rb

	Author: Tamas Koczka & William Webb
	License: BSD 3-Clause

ms16-032: Secondary Logon Handle Privilege Escalation (CVE-2016-099)
https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-MS16032.ps1

	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause

uac-eventvwr: Bypass UAC with eventvwr.exe
https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-EventVwrBypass.ps1

	Author: Matt Nelson (@enigma0x3)
	License: BSD 3-Clause

uac-schtasks: Bypass UAC with schtasks.exe (via SilentCleanup)
https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-EnvBypass.ps1

	Author: Petr Medonos (@PetrMedonos)
	License: BSD 3-Clause

uac-wscript: Bypass UAC with wscript.exe
https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-WScriptBypassUAC.ps1

	Author: @enigma0x3, @harmj0y, Vozzie
	License: BSD 3-Clause
