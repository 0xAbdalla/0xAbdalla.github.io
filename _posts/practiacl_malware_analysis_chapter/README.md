# Practical Malware Analysis Chapter 6

`Lab6-01`

- What is the major code construct found in the only subroutine called by main?
![](/PNG_6/6-1-0.PNG)
The called function is `sub_401000`
![](/PNG_6/6-1-1.PNG)
I think it's `if` condition, because she is calling windows API `InternetGetConnectedState` and store the return value in variable `[ebp+var_4]` and compare with 0 and then take a jump if the value equal zero.
---
- What is the subroutine located at 0x40105F ?
![](/PNG_6/6-1-2.PNG)
-he is call a function `__stbuf` with push edi and esi (he moves in esi offset file i think this file sent from attacker)
-and the call fuction `sub_401282` with push eax as int (Knowing that store value of eax in edi and moves value of stack `[esp+10h+arg_4]` in eax) and push [esp+14h+arg_0] as int and push esi as file 
-and call the function `__ftbuf` with push esi and edi (knowing that edi containing the return value of function `__stbuf`).
---
- What is the purpose of this program?
i think it try to know the state the internet in order to take a feedback.

`Lab6-02`

- What operation does the first subroutine called by main perform?
![](/PNG_6/6-2-0.PNG)
`sub_401000` there is the first subroutine in main
![](/PNG_6/6-2-1.PNG)
uses windows API `InternetGetConnectedState` to know the status of the Internet, where if the return value is true, this means that it is connected to the Internet, and if it is false, this means that it is not connected to the Internet 
---
- What is the subroutine located at 0x40117F?
![](/PNG_6/6-2-2.PNG)
-he is call a function `__stbuf` with push edi and esi (he moves in esi offset file i think this file sent from attacker)
-and the call fuction `sub_4013A2` with push eax as int (Knowing that store value of eax in edi and moves value of stack `[esp+10h+arg_4]` in eax) and push [esp+14h+arg_0] as int and push esi as file 
-and call the function `__ftbuf` with push esi and edi (knowing that edi containing the return value of function `__stbuf`).
---
- What does the second subroutine called by main do?
![](/PNG_6/6-2-3.PNG)
`sub_401040` there is the second subroutine in main
![](/PNG_6/6-2-4.PNG)
-he uses the windows API `InternetOpenA` that the returns a valid handle that the application passes to subsequent WinINet functions. If InternetOpen fails, it returns NULL
-and uses the windows API `InternetOpenUrlA` that the returns a valid handle to the URL if the connection is successfully established, or NULL if the connection fails
-he is try to connection the internet by means of internet explorer and open the website `http://www.practicalmalwareanalysis.com/cc.htm` in order to read some files and doing malicious things.
---
- What type of code construct is used in this subroutine?
![](/PNG_6/6-2-5.PNG)
-I htink it's `if` condition because frequent use of comparisons with jumping
---
- Are there any network-based indicators for this program?
![](/PNG_6/6-2-6.PNG)
IOCs : `http://www.practicalmalwareanalysis.com/cc.htm`
---
- What is the purpose of this malware?
he is try know state of the internet in order to open the internet explorer and the open website `http://www.practicalmalwareanalysis.com/cc.htm` and read some files and doing the malicious activites.

`Lab6-03`

- Compare the calls in main to Lab 6-2’s main method. What is the new function called from main?
![](/PNG_6/6-3-0.PNG)
`sub_401130` there is the new function in main
---
- What parameters does this new function take?
![](/PNG_6/6-3-1.PNG)
`lpExistingFileName` : The current name of the file or directory on the local computer
`char`
---
- What major code construct does this function contain?
![](/PNG_6/6-3-2.PNG)
This is definitely a `switch case`.
![](/PNG_6/6-3-3.PNG)
click on the `tab` will decompile automatically.
---
- What can this function do?
It depends on the input char value. If it is `a`, then it creates directories, if it is `b`, it copies the file, if it is `c`, it deletes the file, if it is `d`, it opens the registry key and then executes the other of the malicious instructions, and if it is `e`, it creates sleep mode for a certain period of time.
---
- Are there any host-based indicators for this malware?
![](/PNG_6/6-3-4.PNG)
IOCs : `C:\Temp\cc.exe`
registry key : `Software\Microsoft\Windows\CurrentVersion\Run`
---
- What is the purpose of this malware? 
he is try know state of the internet in order to open the internet explorer and the open website `http://www.practicalmalwareanalysis.com/cc.htm` and read some files and try to set the registry key `Software\Microsoft\Windows\CurrentVersion\Run` and manipulating files, whether deleting them or creating other files.

`Lab6-04`

- What is the difference between the calls made from the main method in Labs 6-3 and 6-4?
![](/PNG_6/6-4-2.PNG)
![](/PNG/6-4-0.PNG)
---
- What new code construct has been added to main?
![](/PNG_6/6-4-1.PNG)
ooops! this means that the code is repeated 1440 times 
---
- What is the difference between this lab’s parse HTML function and those of the previous labs?
![](/PNG_6/6-4-3.PNG)
i think the different in the number of variables and arguments and he is print the `Internet Explorer 7.50/pma%d` knowing that `%d` is the input and there is the counter. this is mean will print the message 1440 times.
---
- How long will this program run? (Assume that it is connected to the Internet.)
he is the excute the code 1440 times and into the code he is sleep 60000 millisecond 
![](/PNG_6/6-4-4.PNG) try to claculate this :
1440 * 1 minute(60 second(60000 millisecond)) = 1440 minute 
`1 hour = 60 minute --> ? hour = 1440 minute`
the time will this program run is = (1440*1)/60 = 24 hours = 1 days
---
- Are there any new network-based indicators for this malware?
IOCs : `Internet Explorer 7.50/pma%d`
Internet Explorer 7.50/pma1 .... Internet Explorer 7.50/pma1440
---
- What is the purpose of this malware?
It does the same lab6-03 but this works all day.



Thanks 



# Practical Malware Analysis Chapter 7

`Lab7-01`

- How does this program ensure that it continues runnin (achieves persistence) when the computer is restarted?
![](/PNG_7/7-1-0.PNG)
he is create a service named `Malservice`with giving it the paramters, after search in the `MSDN` on the API `CreateServiceA` with the paramters. i detect the value of paramter `dwStartType` equal 2 in MSDN means the `SERVICE_AUTO_START` so it will be turned on automatically.
![](/PNG_7/7-1-1.PNG)

---

- Why does this program use a mutex?
![](/PNG_7/7-1-2.PNG)
he is open mutex named `HGL345` with giving permission to `MUTEX_ALL_ACCESS` to make sure that this process exists.
if the process there exists then exit process, but not exists he is create mutex with the same name and complete another of the rest instruction.

---

- What is a good host-based signature to use for detecting this program?
`Malservice` : to detect this program open the `process hacker` and open the properties of the process and go to the service then exists with same name.
`HGL345` : to detect this program open the `process hacker` and open the properties of the process and go to handle then search of the mutent or mutex it has the same name.

---

- What is a good network-based signature for detecting this malware?
I searched in the imports and then found 2 windows API related to the internet :
![](/PNG_7/7-1-3.PNG)
I went to the source of their calls
![](/PNG_7/7-1-4.PNG)
he is open the `Internet Explorer 8.0` as a User Agent to open the suspicious URL `http://www.malwareanalysisbook.com` as a loop ( The proof is that there is no case that prevents jumping to the same place )

---

- What is the purpose of this program?
in the beggining he is start and create service named `Malservice` 
![](/PNG_7/7-1-5.PNG)
and wait the 2100 years and create thread 
![](/PNG_7/7-1-6.PNG)
this thread inside it infinty loop to connect the URL `http://www.malwareanalysisbook.com` i think this is `DDOS Attack`.

---

- When will this program finish executing?
this program inside it infinty loop, i think will run for infinty untill the killed process by task manager.

`Lab7-02`

- How does this program achieve persistence ?
There are no indications that it will achieve persistance.

---

- What is the purpose of this program?
In the beginning he calls function windows API `OleInitialize` initializes the COM library on the current apartment and call the function API `CoCreateInstance` Creates and default initializes a single object of the class associated with a specified CLSID
![](/PNG_7/7-1-7.PNG)
lets go to calc the GUID of `rclsid` and `riid` :
`rclsid` : data1 -> dd 2df01 -> 0002 df01
           data2 -> dw 0 -> 0000
           data3 -> dw 0 -> 0000
           data4 -> db 0C0h, 6 dup(0), 46h
try to search in registers of the GUId :{0002df01-0000-0000-c000-00000000064}
![](/PNG_7/7-1-8.PNG)

`riid` : data1 -> dd 0D30C1661h -> d30c1661
         data2 -> dw 0CDAFh -> cdaf
         data3 -> dw 11D0h -> 11d0
         data4 -> db 8Ah, 3Eh, 0, 0C0h, 4Fh, 0C9h, 0E2h, 6Eh -> 8a3e00c04f0c90e26e
search in registers of the GUId : {d30c1661-cdaf-11d0-8a3e-00c04fc9e26e}
![](/PNG_7/7-1-9.PNG)
and call the function API `SysAllocString` with paramter the `http://www.malwareanalysisbook.com/ad.html` i think he is try to access the website.

---

- When will this program finish executing?
Once you're done connecting to the site `http://www.malwareanalysisbook.com/ad.html`, I don't think it's going to take much time. 

`Lab7-03`

- How does this program achieve persistence to ensure that it continues running when the computer is restarted?

note : in windows os the all programs use imports of the library `Kernel32.dll` 

In the beginning try to open,read and shared the file in the address `C:\Windows\System32\Kernel32.dll` 
![](/PNG_7/7-1-10.PNG)
and try create file called `Kerne132.dll` and imports all of programs in os refer to the file (Note that there is no difference between the way the names are formatted between the two files, but there is a difference in the names by switching the letter L with 1) through a function called `sub_401040` 
![](/PNG_7/7-1-11.PNG)
![](/PNG_7/7-1-12.PNG)
![](/PNG_7/7-1-13.PNG)
and its copy file of `Lab07-03.dll` to `Kerne132.dll`.
All programs will automatically go to the modern file `Kerne132.dll` which was called `Lab07-03.dll`.
![](/PNG_7/7-1-14.PNG)
this shows that he will achieve persistance.

---

- What are two good host-based signatures for this malware?
file called : `kerne132.dll` not `Kernel32.dll`
Mutex called : `SADFHUHF`
![](/PNG_7/7-1-15.PNG)

---

- What is the purpose of this program?
in the beginning called the API function `WSAStartup` to initiates use of the Winsock DLL and creats a socket with API `socket` and he use  `inet_addr` function converts a string containing an IPv4 dotted-decimal address into a proper address for the IN_ADDR structure. I found the IP that makes a connection through it and it is `127.26.152.13` we can use the IOCs 
![](/PNG_7/7-1-16.PNG)
![](/PNG_7/7-1-17.PNG)
From here it became clear to me that when the malicious file runs, it sends a message to the attacker with the text `hello`, and then the attacker sends `sleep` and then executes the sleep instruction or sends `exec` and then the file completes the execution of malicious instruction by creating a process 

---

- How could you remove this malware once it is installed?
First you must change the file called `Kerne132.dll` to `Kernel32.dll` in order to disable malicious instructions and then backup the system. 





Thanks.





# Practical Malware Analysis Chapter 9


`Lab09-01`

- How can you get this malware to install itself ?
the function that intall the malware by itself is the last function in the code, this indicates that it requires a complete analysis of the file, but this will take me a long time to explain, so I did an analysis of the function only.
the function is called `sub_402600` he is transfer the file into the path `SYSTEMROOT%\system32\Lab09-01.exe` and open a manager service ,create a service with paramter auto start 
![](/PNG_9/9-0-2.PNG)
he is intall itself in `SYSTEMROOT` directory.

---

- What are the command-line options for this program? What is the password requirement?
`-in` : install the malware 
![](/PNG_9/9-0-3.PNG)
`-re` : remove the malware
![](/PNG_9/9-0-4.PNG)
`-c` : check on the number of arguments passed to the program
![](/PNG_9/9-0-6.PNG)
`-cc` :  looks for its current configuration that’s been stored
![](/PNG_9/9-0-7.PNG)

the function is called `sub_402510` he is check the password 
![](/PNG_9/9-0-8.PNG)
in the beginning code is compare the length of password is equal 4 he is the first hint of the password and compare of the first char in password in the decimal equal 97 that indicates the first char is `a` and he is subtract the value of first char,second char and compare the result equal 1 that indicates the second char as value equal 98 in ascii equal `b` and he is multiple result of subtract of , 99 that indicates 99*1 equal 99 in ascii equal `c` and the last char he is add the first char as value in decimal , 3 he is equal in ascii `d` at the end the password equal `abcd`

---

-  How can you use x64dbg to permanently patch this malware, so that it doesn’t require the special command-line password?
inside the function `sub_402510` we patched the instruction `jmp` instead of `je`.

---

- What are the host-based indicators of this malware?
registry key : `SOFTWARE\Microsoft\XPS`
path root : `%SYSTEMROOT%\system32\Lab09-01.exe`

---

- What are the different actions this malware can be instructed to take via the network?
![](/PNG_9/9-0-9.PNG)
i think he is download malfile or upload files.

---

- Are there any useful network-based signatures for this malware?

`http://www.practicalmalwareanalysis.com`




`Lab09-02`

- What strings do you see statically in the binary?
![](/PNG_9/9-1-1.PNG)

---

- What happens when you run this binary?
There's nothing see I can describe.

---

- How can you get this sample to run its malicious payload?
after take the file on x32dbg i will detected this its compare the name file is equal `ocl.exe` if false the file is termnaited , but if true i think he is complete the malcious things.
![](/PNG_9/9-1-2.PNG)
this function is compare `ecx` and `eax` based on take jump or not.

---

- What is happening at 0x00401133?
he is write a string in this location = "1qaz2wsx3edc"
![](/PNG_9/9-1-3.PNG)

---

- What arguments are being passed to subroutine 0x00401089?
![](/PNG_9/9-1-4.PNG)
he passed a str in edx `1qaz2wsx3edc` and memory in dump in ecx `0019FD40` this is value in ecx.

---

- What domain name does this malware use?
the function is called `sub_401089` i did the debugging in the function and the view the value of `eax` and view in dump i found this domain `www.practicalmalwareanalysis.com` 
![](/PNG_9/9-1-5.PNG)

---

- What encoding routine is being used to obfuscate the domain name?
`XOR`
![](/PNG_9/9-1-6.PNG)

---

- What is the significance of the CreateProcessA call at 0x0040106E?
after connecting the malware with c2 server he is create process with paramter cmd to recive the command from auther right away
![](/PNG_9/9-1-7.PNG)




`Lab09-03`


- What DLLs are imported by Lab09-03.exe?
   - DLL1.dll
   - Dll2.dll
   - KERNEL32
   - NETAPI32
   - DLL3.dll (After connecting to C2 Server, it loads this dll)
![](/PNG_9/9-2-1.PNG)

---

- What is the base address requested by DLL1.dll, DLL2.dll, and DLL3.dll?
10000000 = It's the same address in the 3 files dll.

---

- When you use x32dbg to debug Lab09-03.exe, what is the assigned based address for: DLL1.dll, DLL2.dll, and DLL3.dll?
I put breakpoint at address 004010A2 and went to the main function and step into the main and I put breakpoint at address 004010A2 after downloading the DLL3 file.dll then I went to the memory map.
   - DLL1.dll = 10000000
   - DLL2.dll = 00450000
   - DLL3.dll = 00920000
![](/PNG_9/9-2-2.PNG)
![](/PNG_9/9-2-3.PNG)

---

- When Lab09-03.exe calls an import function from DLL1.dll, what does this import function do?
he is import function called `DLL1Print` 
![](/PNG_9/9-2-4.PNG)
and examine xref of location we found in the main and the main he is called the API `GetCurrentProcessId` and the stored return value in the dword i think he print this statment `DLL 1 mystery data /idprocess`
![](/PNG_9/9-2-5.PNG)

---

- When Lab09-03.exe calls WriteFile, what is the filename it writes to?
![](/PNG_9/9-2-6.PNG)
after calling the function `DLL2ReturnJ` the return value of handle is stored in `[epb+hfile]` and passed as paramter to the API `WriteFile` 
let's open the file of DLL2.dll in ida pro 
![](/PNG_9/9-2-7.PNG)
and examine xref of location we found the main that is create file named `temp.txt` and the store the return value in the dword
the filename it write to = `temp.txt`

---

- When Lab09-03.exe creates a job using NetScheduleJobAdd, where does it get the data for the second parameter?
let's to show the decompiled the main function and specifically at `NetScheduleJobAdd`
![](/PNG_9/9-2-9.PNG)
the second paramter is buffer and the buffer return of DLL3GetStructure and the function is import of DLL3.dll 
let's open the file of dll in ida 
![](/PNG_9/9-2-10.PNG)
the function `DLL3GetStructure` content of dword we examin xref will found in the main 
![](/PNG_9/9-2-11.PNG)
he is call API `MultiByteToWideChar` after search in MSDN about of API will found there is maps a character string to a UTF-16 string and search of `NetScheduleJobAdd` in MSDN will found 
![](/PNG_9/9-2-12.PNG)
the buffer used as pointer in scheduled task to ping the url `www.malwareanalysisbook.com` , after calc the 3600000 milisecond equal 60 minute then the task scheduled is ping the url every day one hour after the beginning of the day 

---

- While running or debugging the program, you will see that it prints out three pieces of mystery data. What are the following: DLL 1 mystery data 1, DLL 2 mystery data 2, and DLL 3 mystery data 3?
i think i explained it in question(4,5,6)
DLL1 = print process current id 
DLL2 = print handle of created the file (temp.txt)
DLL3 = print widechar during the ping url

---

- How can you load DLL2.dll into IDA Pro so that it matches the load address used by x32dbg?
![](/PNG_9/9-2-13.PNG)
![](/PNG_9/9-2-14.PNG)





thanks.







# Practical Malware Analysis Chapter 11


`Lab11-01`

- What does the malware drop to disk?
after open file in resource hacker i found the binary file called `TGAD`
![](/PNG_11/11-1-2.PNG)
i think this file is dropped but i complete Dynamic analysis :
after run file i found file called `msgina32.dll` in disk this file is dropped in disk 
![](/PNG_11/11-1-3.PNG)

---

- How does the malware achieve persistence?
by file `msgina32.dll` and the registry key `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GinaDLL`

---

- 








