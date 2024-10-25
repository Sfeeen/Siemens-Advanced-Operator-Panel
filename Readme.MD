## AOP requires rebuild - Writeup of my reverse engineer approach
I'm an R&D engineer at an electronic repair company and an overall enthousiast of reverse engineering hardware and software. When encountering a 'dead' AOP panel at work with no available solution to fix this piece of hardware I wass triggered to investigate this at home in my spare time.

 As trying to provide a way for people to restore there AOP in an easy way would be nice, it is not my main goal. I choose this project because I would like to glitch out firmware from a secured microcontroller and to reverse engineer microcontroller firmware. I have no practical experience in the former and a very brief experience in the latter and was hoping to develop it during this project. 

 The structure of this writeup is lineair in time and genuine. Meaning I just write my approaches and efforts along the way, and if, after gettings smarter they are deemed irrelevant or there were incorrect assumptions I still let this be part of this writeup. 


## Siemens AOP

Siemens AOP (6SE6400-5AP00-0BB0
) is an Operator panel used to communicate with Micromaster drives. It has more features this basic brother 'BOP' hence the names Advanced Operator Panel and Basic Operator Panel.

<img src="Images/AOP_front.jpg?raw=true" alt="AOP Front" title="AOP Front" width="300"/>

Some of its functions are:
- It can upload and download parameters sets from a drive
- It can scan RS232 and RS485 ports for drives
- You can view / edit drive parameters with the display and buttons.

## Problem when battery is low or removed
It can stop working and its display would say : 
```
AOP is slave to PC! 
AOP requires rebuild 
P to exit when done
```

![Error message on AOP](Images/AOP_requires_rebuild.png?raw=true "Error message on AOP")

The cause of this is that the internal coin cell battery was either removed or dropped to much in voltage over the years.
According to [this thread](https://support.industry.siemens.com/cs/document/21367554/micromaster-4-(aop)-lifetime-and-exchange-of-the-aop-battery?dti=0&lc=en-BE) it should last 5-8 years on a single coin-cell. You could replace this battery if you happen to think about this before it runs out. But let's not kid eachother, nobody does since there is no indication for it on the display. There is however an internal parameter P8560, where you could check this battery level. But again it requires the user to think about this actively...
[Update: thats a lie, there is actually a battery low warning on the screen, it would however have made for a better incentive for this project]

## Known solutions 
From the manual, you get no help. It doesn't even mention this fault. From the internet the only suggestion I find is buying a new one, but that seems kind of a waste. Let's try to save some bucks and try to solve it ourselves. 

## Reverse engineering the AOP hardware
Let's open up this display and see what we are working with:

<img src="Images/pcb_battery_side_stickers.jpg?raw=true" alt="AOP Front" title="AOP Front" width="300"/>
<img src="Images/pcb_mcu_side_stickers.jpg?raw=true" alt="AOP Front" title="AOP Front" width="300"/>

Okay, whenever I reverse a PCB like this, I start up by taking note of all the chips and there function. 
Reading all the markings I get:

<img src="Images/AOP_chip_annotations_battery.drawio.png?raw=true" alt="AOP Front" title="AOP Front" width="500"/>
<img src="Images/AOP_chip_annotations_mcu.drawio.png?raw=true" alt="AOP Front" title="AOP Front" width="500"/>

Looking up all the datasheets we can get a simple idea of what each chip does:

Chip marking | Short function 
--- | --- |
2144B69FAV SIEMENS A&D | Microcontroller 
ACT/P8 | 16Mhz Crystall
HA573 | Octal latches
SAMSUNG K6X4008C1F-UF55 | CMOS SRAM
AHC00 | quad NAND gates
AHC08 | quad AND gates
L4931C50 | 3.3V LDO
74VHC32 | quad OR gates
HA74 | flip flop
MAX691A | supervisor
ADM202EA | RS232 line driver
PCF8563 | Real-time clock/calendar
32.768k | 32khz Crystall

Okay since the removal of the battery causes the issue, we want to check which chips are powered from this battery.

It seems the battery is only connected to the supervisor (MAX691A), the SRAM (K6X4008C1F-UF55) and the RTC (PCF8563). 

<img src="Images/battery_powered_chips.png?raw=true" alt="AOP Front" title="AOP Front" width="500"/>

Okay from this we could guess what goes wrong.
I would assume the microcontroller performs all the logic and only uses the SRAM to store the drive-parameter sets it has uploaded. Though it could be that they wrote a bootloader with which they loaded some configuration into the SRAM. Alternatively the real time clock might need a valid datetime setting to work. Off course a combination of both could be the case as well.

One solution could be to read out the RTC / SRAM in circuit. Though I'd assume the connections to the MCU would alter our signals (a not powered mcu likely has some low impedance connection to ground on its IO). Apart from that it would also take us some effort.

Another option would be to attach a battery to the supply of the chips and them trying to desolder them without shorting any connections while desoldering and off course while not desoldering the batteryleads. An even more effortfull and risky solution if you would ask me, well for the SRAM at least. And we would need a working unit (I don't have one for now).

The cleanest solution I could think of would be trying to dump the MCU's firmware. Writing a program for this chips that reads the RTC and SRAM's content of a working AOP and reflashing the original firmware. Then the contents of a broken AOP could be restored in a similar fashion.

But no cigar there, the chipname 2144B69FAV SIEMENS A&D doesn't seem to give use any hits in google. Of course it being branded a 'SIEMENS'-chip at would not bring much hope. Seems like they bought or developped a custom MCU...

Fortunately I have a second broken AOP laying around. The PCB design seems totally identical, except for 2 chipmarkings...

The SRAM seems to be a CY62148ELL-45ZSXI on this one. The marking on the MCU: F2144AFA20V H8S/2144A
bingo! This brings some hope back, they nonetheless used an off-the-shelf MCU. Maybe they rebranded them in an effort to counter the dumping of the chip / make RE more difficult.

<img src="Images/renesas_datasheet.png?raw=true" alt="AOP Front" title="AOP Front" width="500"/>

Okay we are dealing with a chip from Renesas. The datasheet is revisioned in 2006 so the chip is already quite old... Lets hope it supports upload functionality.

I started out by searching for the flash program software for this MCU. It seems to be conveniently named [Flash development toolkit](https://www.renesas.com/us/en/software-tool/flash-development-toolkit-programming-gui).
Let's spin up a Windows XP virtual machine in VMWare as I assume this program was developped in tis era. Install the software and creat a new project.

<img src="Images/FDT_project.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

When proceeding on making the project it ask us the type  of controller. It knows the 2144 type we have so that's good. Then it asks us for a serial port for our connection to the chip. Perfect! Gives use some hope we don't need to buy a specific debugger / programmer to program/upload these chips. 

<img src="Images/serial_port.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

<br>

> Sidenote: Serial port is a PC port people often had on older pc's dating from the DOS, Windows XP era. I know it for it being used to communicate with (old) industrial electronics (PLC's, frequency drives, ...). But in fact it can be used for whatever communication you want. It is UART communication on RS232 levels. 

For the CPU frequency the software suggests 20Mhz but let's change it to 16Mhz because of the crystall on the PCB.

<img src="Images/cpu_frequency.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

<img src="Images/connection_type.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

Next the connection type... We can choose between BOOT Mode and USER Program Mode. The former seems to erases its flash prior to connect. Well, let's NOT choose this one. 

<img src="Images/User_program_mode.png?raw=true" alt="AOP Front" title="AOP Front" width="400"/>

USER Program Mode assumes we have a USER micro kernel installed. I don't  really know what this means but I assume its a bootloader similar like the one in an Arduino (Optiboot). Which enables a user to program it using serial. Let's just hope it is there.

As for the communication speed I just go with the default.

When the project is set up we go look for an upload method.

<img src="Images/upload_menu.png?raw=true" alt="AOP Front" title="AOP Front" width="400"/>
<br><br>'Device' -> 'Upload Image' seems what we need. Lets select the whole user flash region and hit  upload. <br><br>


<img src="Images/upload_region.png?raw=true" alt="AOP Front" title="AOP Front" width="400"/>
<img src="Images/COM1_upload.png?raw=true" alt="AOP Front" title="AOP Front" width="400"/>

I have nothing attached yet ofcourse so it doesn't read out anything but we can see from the debug window that it tried to communicate using COM1 with my chip, perfect. Let's figure out how to connect with the MCU.

The chip's manual didn't help me much there but I found another pdf: [Renesas Flash Programmer  
Sample Circuit for Programming  
by Using a PC’s Serial Port](https://www.renesas.com/document/man/renesas-flash-programmer-sample-circuit-programming-using-pcs-serial-port).

We have 3 connections options: 
- Type A circuit
- Type B circuit
- Type C circuit

Let's work with type B circuit since in the software I see we are apparently using 'Protocol B' let's assume this reflects the connection circuit. 

<img src="Images/circuit_type_hint.png?raw=true" alt="AOP Front" title="AOP Front" width="400"/>

<img src="Images/type_b_circuit.png?raw=true" alt="AOP Front" title="AOP Front" width="400"/>

Okay, we need a RS232 to TTL converter chip. As from our chip markings we have seen that there is such a transceiver present on the PCB (ADM202EA).
Lets find out where pins FLMD0, TOOL0 and _RESET are located an how they are routed on the pcb.

<img src="Images/MCU_pinout.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

Well no hits there, the datasheet doesn't seem to get any references on these names.
Let's take another approach and start from the RS232 transceiver and see how it is routed. We are only interested in the T/R IN/OUT connections, let's trace them.

<img src="Images/transceiver_pin_configuration.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

The second channel doesn't seem used since T2in connects to ground. T1in and R1OUT seems to be connected to pin 97 and 98 (TxD1 and RxD1).
The RS232-leveled signals seems to go through 1k-resistors and one goes to pluggable connector, the other only to a testpin.

Okay, with that info lets re-evaluate our PC - MCU connection choice (type B). Maybe it's not what we need since we don't have those pins and since the relation to the 'Protocol: B' in software was just a wild assumption.

Type A also uses the FLMD0 pin, but looking at type C, this one might be a fit.

<img src="Images/type_c_circuit.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

The pins required on the microcontroller seem to somewhat match what we got available.

TxD <-> TxD1
RxD <-> RxD1
MD0 <-> MD0
MD1 <-> MD1
RESET <-> /RES or /RES0

<img src="Images/MCU_pinout_com_highlighted.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

Let's make Type C circuit our new assumption and check what the current connections for MD0, MD1 and RESET are. From the circuit definition MD0 and RESET should be high, MD1 should be low.

<img src="Images/MD1_connection.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

- MD0 has a hard ground.
- MD1 is pulled up to VCC and is connected to  to  on-board dip-switch pin-1. Which when enabled pulls MD1 low.
- /RES  is connected to /RESET of the supervisor

It's quite a big datasheet so let us ask chatGPT what these pins do.

<img src="Images/chatgpt_MD_functions.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

Okay, the difference between required upload configuration and current configuration seems to be the enable of the on-chip ROM. Not sure if this really effects the ability to perform a upload/download though...

Trust ChatGPT but verify:

<img src="Images/verify_md_function.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

Let's meet in the middle, we put MD1 to ground with the dipswitch but let MD0 be tied to ground. We go to the software and hit upload!

No luck. Maybe it's handy to get a view of what is happening on the serial port. For that I use some software called IO ninja and use it's serial monitor function. I enable it on COM3 because thats my serial port. After enabling the monitor I pass it through to my WINXP VM where it can be found as COM1.

<img src="Images/IO_ninja_serial_monitor_upload.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

We can tell that the software opens up the COM-port with the following settings:
- Baudrate: 9600
- Data bits: 8
- Stop bits: 1
- Parity: None

For short 9600 8N1, the most common communication setting.

As for what the software sends  we see '0000 27'. Maybe I should search the internet on some more info about programming this or similar MCU's. After some searches I found this: [System Specifications for Standard Boot Firmware](https://community.renesas.com/the_vault/other_products/h8/f/h8---forum/27943/how-to-program-a-h8-3067-microcontroller) It's about a different kind of microcontrollers (RA series) but it contains some info about the Serial Communication Interface (SCI).

<img src="Images/SCI.png?raw=true" alt="AOP Front" title="AOP Front" width="800"/>
Okay this seems to match our baud settings. We also learn that the software should put RxD low for the MCU to do some initialisation and respond. I'm assuming the 4 zeros we saw do just that. Unfortunately our MCU isn't responding yet, but okay I'm aware I didn't had the signal settings right. Let's do it good this time.

I disconnected MD0 from its fixed ground connection by physically pulling the pin high and attaching a wire, after which I pulled it high again (from an electronic standpoint this time).

<img src="Images/MD0_wire.jpg?raw=true" alt="AOP Front" title="AOP Front" width="800"/>

- Here you see the wire on the cpu that is attached to MD0 and the 2 other wires are for a 3V3 supply.

Trying the upload once again yields no result. The CPU seemed properly powered, MD0 was high, MD1 low, as requested. But then I checked /RESET again, hmm it was low the whole time so the CPU isn't even running. I didn't think about this signal much untill now. After some measuring I figured the supervisor is keeping it in reset because it's VCC signal is below its threshold. Turned out I also naively assumed that the CPU needed a 3V3 supply but it turns out it needs 5V (the threshold of the supervisor chip is 4.65V).

Now all 3 signals are okay, I give it another go ... still no cigar :/

From the serial traffic it seemed that the cpu didn't reply in any way so either there is no bootloader listening on this serial connection or I'm still doing things wrong.

I decided it would now be a good idea to fully reverse the schematic of the PCB so I have a clear view of everything.

After spending several hours I was finally done retracing all electronic paths in Kicad and was represented with: 

<img src="Images/HW_reverse_engineered.png" alt="AOP Front" title="AOP Front" width="800"/>
<img src="Images/HW_reverse_engineered_shematic.png" alt="AOP Front" title="AOP Front" width="800"/>

This soothing RE process brought me the following relevations: 
- Its a 4 layer PCB with a GND layer and a 5V layer in the middle. signals on the outside (lucky me!)
- PB7 and PB3 seem to be some configuration pins (see image below). The PCB provides footprints to solder a pulldown and a pullup resistor (pulldown not installed). Might be interesting to determine what can be configured with these pins when reversing the firmware.
- SCI0 goas to the plug connector.
- RES0 from the MCU is not connected
- P82 can switch the battery voltage with a BJT which then goas to P72 of the mcu?
- P83 / Q3 can switch the power to the supervisor to ground. 
- The signals going to the pinheader for the display doesn't make much sense to me since they are also connected to the SRAM. And some other signals come from the flip flop. 

<img src="Images/configuration_pins.png" alt="AOP Front" title="AOP Front" width="400"/>
<br>
(Configuration pins)
<br><br>

<img src="Images/weird_display_connections.png" alt="AOP Front" title="AOP Front" width="400"/>
<br>
(weird display connections)
<br><br>

Having all the electronical connections between the chips clears some questions but gives rise to others...

But what this shematic certainly tells me is how to properly power the board: VIN must be 5.5V - 20V and from this supply 5V Vcc will be made.

Now I had the device powered the proper way I tried communication again, again with no luck.
After some time I decided to resolder the display to the board (I disoldered it for making the Xray scan). What I was afraid for happend: the display doesn't work anymore, I see only the backlight going on. When removing the display I used a hot air gun to melt the solder but because I wasn't to carefull and an unhealthy spot arised in the LCD cause by the heat. When cooling down the LCD looked normal again but I has now been confirmed that I must have broken the LCD. Unless it's the microcontroller that has accidentally died in the mean time...

I checked some signals from the MCU with my oscilloscope and I saw it 'being alive', meaning it did set some pulses on some pins making me believe that it is certainly the display that is broken.

Another day, another approach. Temporarely tired from establishing software communication I wanted to take a closer look to the RTC. It has an I2C interface. I soldered some parallel wires to SDA, SCL and GND and tried to read its configuration from a library I found online. Using the address I found in the datasheet (A3h and A2h). Sadly the code seemed stuck on the chip initialisation. 
Then I decided to try the I2C scanner sketch. No luck.
Highered the address loop because it only goes to 128, while A3 is hex for 163. But again no luck.

Further analysing using my oscilloscope got me smarter: the MCU is not powered and in this state it's SDA and SCL pins have some impedance to ground which is low enough to not make my I2C communications signals valid. So I decided to power the MCU while my Arduino tries  to read/detect the RTC. Guess what? When the MCU is powered the SDA and SCL signals where to strongly pulled up so my problem remained. Finally, partly against my will I decided to cut the traces to the MCU. That eventually made reading and configuring this RTC possible. 

While there is a chance that putting a valid date into a broken AOP might solve the problem I don't have high hopes for this. I can't even test this right now since I wouldn't be able to confirm the workings with my broken display. But anyway this would take away the fun of exploring the MCU's firmware...

Exploring the internet some more I realised the H8S/2144 chip can also be named HD64F2144. This then brought me to the conclusion that there exists an [Elnec adapter](https://www.elnec.com/en/products/programming-adapters/DIL48_QFP100-1_ZIF_H8S-4/) with which to firmware of the chip could be read with Beeprog. I do have access to this programmer at work, unfortunately I do not have 280.0 € to spend for an adapter. But at least it gives me somewhat certainty that readout of this chip is possible, and in the explanation in the beeprog software there are no indications of readout security.

The datasheet that made me notice that H8S/2144 <-> HD64F2144 was:
https://www.ele.uva.es/~jesman/BigSeti/ftp/Microcontroladores/Hitachi/H8-300H/h8_16bit.pdf
Apart from this obvious aspect it also made RxD0/TxD0 more obvious. Which made me think: maybe instead of SCI1 I need to use SCI0?? (SCI = Serial communication interface by the way).
These signals are connected to the pluggable connector but in its pure TTL form (no RS232 transceiver). I tried it with a TTL converter attached to my pc but still the same miserable results.

Then I focused some more on starting with a working, clean chip. Like the programmers from siemens would have prototyped with when designing this board. In other words I tried to find a starters kid for this MCU. In [another manual](Manuals/h8s_renesas_mcus.pdf) I found The 2144 didn't seem to have one but the most similar one for which such a kit exist seemed to be:
H8S/2166 starters kit with part number: 3DK2166
<img src="Images/starters_kit.png" alt="AOP Front" title="AOP Front" width="800"/>
While the starts kit of the H8S series are still 'active' according to Renesas (https://www.renesas.com/en/products/microcontrollers-microprocessors/other-mcus-mpus/h8s-family-mcus/h8s2456r-starter-kit-renesas-starter-kit-h8s2456r) I don't seem to find a seller anywhere for these, also no one selling these on Ebay. Quite unfortunate.

Another free moment later I decided to optimise my setup. It was clumsy because I always soldered and desoldered wires to the PCB for power, signals. 
I also got hold of a working AOP from work but don't want to risk breaking this one in any way. 
To more fluently power AOP's and listen to the signals comming out of the pluggable connector I discovered there exists this I/O adding module for the micromaster called 1790L811A on which you can plug the AOP. 
<img src="Images/1790L811A.jpg" alt="AOP Front" title="AOP Front" width="800"/>
We had a broken one laying around at work which I transformed to easily power and communicate with my target PCB:
<img src="Images/IO_module_1.jpg" alt="AOP Front" title="AOP Front" width="400"/>
<img src="Images/IO_module_2.jpg" alt="AOP Front" title="AOP Front" width="400"/>
<img src="Images/IO_module_3.jpg" alt="AOP Front" title="AOP Front" width="400"/>

Another day again, I choose to put my focus on the broken display. I was willing to buy a new display. 
I started to google search for it using the keywords I could read on the pcb "VLUK2089 display".
No results but I came across this [website](https://s7detali.narod.ru/MM4_AOP/MM4_AOP.html):

<img src="Images/russian_website.png" alt="AOP Front" title="AOP Front" width="800"/>

With the text - I quote - "при вынимании батарейки
превращается в труп"
which translates: 'when you take out the battery
it turns into a corpse'. This made me laugh in a way while also feeling miserable as I have no real progress into a solution for this currently...

Apart from this they do seem to have pretty images of the AOP and display (which made me hit my google search). I didn't know till now that google forms results based on OCR performed on webpage images.

Since the image of their AOP-PCB is also very clear, you could easily read the chipmarking of the MCU: HD64F2144FA. It was not a Siemens rebrand it seems and also a plus for them: there display is removable, to bad mine wasn.'t...
Anyway nothing quite new it seems but this made me lookup this specific code in the datasheet:

<img src="Images/HD64F2144FA.png" alt="AOP Front" title="AOP Front" width="800"/>

Learning us this is the F-ZTAT version. 
Around the same time I got response on a help-ticket I submitted to Renesas support regarding my inability to communicate with this chip:

<img src="Images/renesas_programming_ticket.png" alt="AOP Front" title="AOP Front" width="800"/>

After this I asked for the F-ZTAT program and received some exe after which the ticket got closed. On the renesas website only updates for the F-ZTAT software could be downloaded now. But on the Japanese website of Renesas I was able to find some demo software.

Also I searched the web for more info on this F-ZTAT program and what the process was to program a chip using this program. The exe's or installer packages I currently got didn't seem to be a full program. They don't start or they ask for certain files. 

- https://www.apnet.co.jp/eng/products/flash2.html#dl
- https://web.archive.org/web/20020401144908/http://www.apnet.co.jp:80/hghome/product/superh/flash.html
- https://www7b.biglobe.ne.jp/~kenjia/J_H8.html#h8k
- https://download.csdn.net/download/qq_43598101/87614191?spm=1003.2122.3001.6634.19
s

I learned that the program is actually called Flash Writer PRO (2) and should look something like this:

<img src="Images/flash_writer_pro.jpg" alt="AOP Front" title="AOP Front" width="800"/>

The program I received from Renesas wouldn't even start, it seems to require a certain .inf file:

<img src="Images/fztat_inf.png" alt="AOP Front" title="AOP Front" width="800"/>

Also from my search journey I somewhat understood that this program has no upload function. 

The [Single Power Supply
F-ZTATTM
On-Board Programming
Application Note](Manuals/REN_rej05b0520_onboardprg_APN_20041213.pdf) gave me some more info. 

The program setup would look like: 
<img src="Images/fztat_connection_setup.png" alt="AOP Front" title="AOP Front" width="800"/>
Unfortunately, if right this would mean I would need this programming adapter.

The communication with the chip seemed to have a different initialisation that the '0000 26'. So that might work.
<img src="Images/fztat_communication.png" alt="AOP Front" title="AOP Front" width="800"/>

It seems like you would want to have a information file for your type of chip which holds the Flash memory block info. (I don't have it).
<img src="Images/inf_file_fztat.png" alt="AOP Front" title="AOP Front" width="800"/>

Furthermore I find no references when looking for 'Upload'. So it might be that it's not supported on F-ZTAT hardware...


Hardware manual page 683 and following are interesting but to me a bit confusing. 
The chip has 128 kbytes of ROM memory. But the pins MD1 and MD0 define if this ROM is enabled or not? What happens if it is disabled, from where should the application code then be loaded? The EXPE (expanded) bit expands the memory range.
I am assuming now that the external SRAM on the board is an memory extension that might store a part of the application code. I first assumed/hoped this would store some drive parameter sets. If true this makes the project quite harder.


<img src="Images/page_683.png" alt="AOP Front" title="AOP Front" width="800"/>


>21 sept '24 | At this point there is a lot unclear for me, and not having a board to experiment with or the knowledge if readout functionality has gotten me a bit 'stuck'. 
If you have further knowledge, idea's, possible approaches or anything that could help please contact me at svenonderbeke < at > gmail < dot > com
 
>30 sept '24 | I'm not stuck anymore. Insights still welcome though.

I was able to find another broken device at work which also uses a H8S-chip. H8S/2633 to be specific. I'll give it a try to communicate with this one. 

<img src="Images/H8S_2633.jpg" alt="AOP Front" title="AOP Front" width="800"/>

There is a 10-pin connector right of it with below some silk-text 'LINK' so this is probably the connector to program this CPU. Let's grab a multimeter and see to what pins they connect.

<img src="Images/H8S_2633_pinout.jpg" alt="AOP Front" title="AOP Front" width="800"/>

Hmmm we got SCI4, power pins and some transmit and random pins. Let's check the manual if SCI4 seems for programming. 

<img src="Images/H8S_2633_programming.png" alt="AOP Front" title="AOP Front" width="800"/>

From the part above it seems to be SCI2. On the left of the board a bit further away from the CPU and on the back side is another 10-pin connector. We'll figure out this pinout as well:

<img src="Images/H8S_2633_pinout2.jpg" alt="AOP Front" title="AOP Front" width="800"/>

Okay this is definately the programming connector, having the reset pin, SCI2 and the FWE and MD2 pin

I attached MD2 to GND and FWE to VCC using a small resister since I had no wires easily available. Then I tried communication with the software and oh yeah, it just worked!
At this point I decided that I wanted to be able to work on this from inhouse, not from my shed where my variable powersupply and 
oscilloscope where. I was powering the device from the 12V rail but wanted to power on the 5V so I could have my setup laptop-powered.
The VCC of my FTDI USB to TTL adapter didn't cut it to power the 5V-line of the board but I knew the board was drawing around 200ma on this line.
So I cut a USB cable and made it a seperate power cable. This is a picture of my 'portable' setup:
<img src="Images/2633_working_setup.jpg" alt="AOP Front" title="AOP Front" width="800"/>

The 'succesfull-communication-achievement' gives me some room for experimenting again. I tried programming some random data and uploading it, that seems to work ok. 

What I learned was the I could could only connect once per powercycle using the BOOT-mode. From the log output you indeed see that it erases the flash content. It also installs the micro-kernel. After one connection you can reconnect if you pick the user-mode with kernel active. I've you download a file, you can only retrieve this file (upload) within the same boot cycle otherwise the whole content would be 'FF'.

<img src="Images/FDT_2633.png" alt="AOP Front" title="AOP Front" width="800"/>



<img src="Images/communication_successfull.png" alt="AOP Front" title="AOP Front" width="800"/>

My next goal would be to understand and replicate the serial communication that performs connection, download, upload, etc... 

Fortunately the software itself is very verbose on what it is doing on a communication level.
most of the actions are even explained in the F-ZTAT manual and I was able to identify the 'auto-bit rate matching', 'write control program transfer' and the 'application program transfer' in the 
intercepted serial communication. In the picture above you can see the bit rate matching and a handshake before the micro-kernel transfer.
And the snippets below show those parts in the manual.

<img src="Images/bit_rate_matching.png" alt="AOP Front" title="AOP Front" width="800"/>
<img src="Images/auto_bitrate_matching_boot_mode.png" alt="AOP Front" title="AOP Front" width="800"/>
<img src="Images/write_control_program_transfer.png" alt="AOP Front" title="AOP Front" width="800"/>

With the help op ChatGPT I was able to replicate these first actions in no time.

<img src="Images/chatgpt_bit_rate_matching.png" alt="AOP Front" title="AOP Front" width="800"/>

This is an oversight of the communication flow; setting up the connection, writing micro-kernel and main kernel and performing 
an upload.

<img src="Images/FDT_communication_flow.jpg" alt="AOP Front" title="AOP Front" width="800"/>

Only the steps of writing the kernel and the auto bit rate matching are explained in the manual.
Some parts were determined from the verbosity of the FDT program and some things are still unclear.

The writing of the main-kernel is answered by a 0x06 (ACK) command. Then comes the first totally unknown command (0x4F).
Searching google led me to another manual which gives me a name or short description for some commands (not all).
This one seemed to be the 'Boot program status inquiry':

<img src="Images/inquiry_selection_commands.png" alt="AOP Front" title="AOP Front" width="800"/>

Anyhow without understanding every single bit of the communication I ported it to python and I am able to download kernels
myself now and perform upload. 

One interesting remark that I discovered while doing this:
first in the log it says:
... Using micro-kernel '...\uGen2633.cde' 
and then it transmits this exact file.
Then after some commands it says:
.... Downloading main kernel '...\Genm2633.cde' 
and then it downloads something different. I had to export the main kernel that it is really sending from IO-ninja
because I couldn't find a file with matching content. The data shows similarities to 'Genm2633.cde' but isn't exact the same and differs in length.

That little thing aside, it's time to come with a plan of attack!
My assumption is currently that the micro-kernel gets downloaded and then executed, I assume (hope) it
contains the instruction to erase the flash memory. 
I divided my goal in these smaller steps:
- Reverse engineer the micro-kernel of the H8S/2633
- Patch the micro-kernel to skip the erase, perform an upload.
- Perform same steps for the H8S/2144
- Read out its firmware
- Write a RAM-reader and RTC-reader
- Write program that automates the whole process of reviving an AOP

I'm aware there might be some pitfalls along the way and that this whole idea might fail. But for now
it gives me some path to follow and most importantly, for those who remember my goals I hoped to perform in the beginning:
- Reversing firmware
- Glitching a chip to upload its program (okay I will not glitch it, but patching the micro-kernel to unlock an upload which is not provided 
seems already like equally fun).

Writing the steps down made me think about a book I started reading yesterday. 
I actually never read books but I came accross this one named 'Microcontroller Exploits' from Travis Godspeed and I had to have it.
As you can probably guess its not a novel or a thriller but some techniqal literature about different microcntrollers
and how to make them perform something they are not intended to do. 
And in the first few pages I already got some good advice:

<img src="Images/microcontroller_exploits.jpg" alt="AOP Front" title="AOP Front" width="800"/>
<img src="Images/microcontroller_exploits_1.jpg" alt="AOP Front" title="AOP Front" width="800"/>

"If at all possible, don't skip the step of compiling and running Hell World on your target!".

And one should not skip some good piece of advice, so let's prepend this to our list from before.

# Step 0: Greeting the world

To program for a H8S device the 'High-performance Embedded Workshop' - HEW for short - software was developped. 
I was able to find it on the internet.

After going to the steps of setting up a new project I got this:

<img src="Images/HEW_greeting_the_world.png" alt="AOP Front" title="AOP Front" width="800"/>

In this era of microcontroller programming I assume program space was so expensive because during the steps
I had to choose how big I want the stack and heap to be. Never had that before...

Let's try to find some programming guideline for the H8S.
On youtube I only find some short videos from Digikey:
https://www.youtube.com/watch?v=oP-DdDqkkw8

They do however reference to more documentation on www.renesas.com . This reference is now outdated actually
but using the internet archive I got presented with this interested page listing information about H8S and HEW topics.

https://web.archive.org/web/20100722144159/http://www.digikey.com/PTM/PTMMaster.page?site=us&lang=en#Renesas-Technology-America
<img src="Images/webarchive_h8s_info.png" alt="AOP Front" title="AOP Front" width="800"/>

They all lead to a page explaining a topic with the use of the old flash format.
Flash is of course not supported anymore but Internet Archive has 'Ruffle' builtin in, a player use can use to play flash files nowadays.
Unfortunately it didn't seem to work. It's stuck on 100% loaded. 
I found out you had to open this flash page (.swf) seperately and then you have a right mouse option 'play' to start the Flash animation.

I downloaded all the HEW and H8S Flash animations and included them in this repo together with the Ruffle executable to play these files.
The documention made me have a better understanding of the H8S chips and HEW software.
<img src="Images/ruffle_flash.png" alt="AOP Front" title="AOP Front" width="800"/>

What I didn't find was some programming info (How to toggle a port, how to send something using the serial port).
The closest thing to some programming info I found was: 
https://llvm-gcc-renesas.com/getting-started/hew/index.html

I decided to just go and try to make the program from the info given in the H8S/2633 manual.
I have decided I want my testprogram to do the following:
+ Toggle the buzzer that is attached to pin PWM0_A6_PC6 a few times. 
+ Send "Hello world" over SCI4 because this one goes to the connector on the board.


To used the named registers I had to import "iodefine.h".
Then for using the SCI4 port p804 and further is quite interesting. Its shows which registers to set
to send serial data over a port. I had never had the need before to do this on this low level.
I usually have a library so that I just have to run "Serial.begin()" and "Serial.println()". but now
its a good opportunity to get to know how it works on the register-level.

<img src="Images/SCI_workings.png" alt="AOP Front" title="AOP Front" width="800"/>


Well after some night spend on getting this code fixed, I settled with this being 'OK' to move
on to the next step. Getting so far to get the buzzer on or of was not so difficult, but I couldn't
get the serial to work. The core problem is that I never could get the TDRE bit of SCI4 to be one.
It always stayed '0'.
I asked a collegue at work but didn't find out why it isn't working.

This was  the code I settled on:

``` /***********************************************************************/
/*                                                                     */
/*  FILE        :setbuzz.c                                             */
/*  DATE        :Sun, Oct 06, 2024                                     */
/*  DESCRIPTION :Main Program                                          */
/*  CPU TYPE    :H8S/2633F                                             */
/*                                                                     */
/*  This file is generated by Renesas Project Generator (Ver.4.16).    */
/*                                                                     */
/***********************************************************************/


void main(void);
#ifdef __cplusplus
extern "C" {
void abort(void);
}
#endif

#include <machine.h>
#include "iodefine.h"  // Include register definitions

void delay_ms(unsigned long ms);  // Function declaration for delay
void beep(unsigned int amount); 
void sci4_init(void);   
void sci4_send_char(char c);      // Send a single character over SCI4
void sci4_send_string(const char *str);  // Send a string over SCI4
volatile int i;          

void main(void)
{
    // Set PC6 as an output pin
    PC.DDR |= (1 << 6);  // Configure PC6 as output
	
	beep(2);
	
    sci4_init();
	
	beep(3);
	
	// Step 3: Transmit "Hello, world!" over SCI4
    sci4_send_string("Hello, world!\n");
	
	beep(4);
		// Step 3: Transmit "Hello, world!" over SCI4
    sci4_send_string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

	beep(5);
    while (1) {
        // Toggle PC6 (buzzer)
        PC.DR.BIT.B6 ^= 1;  // Toggle PC6 state (0 -> 1, 1 -> 0)
        
        // Wait for 1 second (1000 ms)
        delay_ms(1000);
    }
}

// Function to initialize SCI4 for 9600 baud communication
void sci4_init(void)
{
	SCI4.SCR.BIT.TE = 0; 
	SCI4.SCR.BIT.RE = 0; 
	
	
	SCI4.SCR.BIT.CKE = 0; 
	
    // Set the baud rate for SCI4 (Assume PCLK is 20 MHz, for 9600 baud)
    SCI4.SMR.BYTE = 0x00;  // Set clock source and mode
	SCI4.SCMR.BYTE = 0xF2;
    SCI4.BRR = 38;         // Baud rate setting for 9600 baud (PCLK / (16 * (64 + 1)))

    // Wait for the baud rate setting to stabilize (about 1 bit time)
	//unsigned int i = 0;
    for (i = 0; i < 1000; i++);  // Short delay for stabilization
	
	// Enable transmission
    SCI4.SCR.BIT.TE = 1;   // Enable transmission
	// Enable transmission
    SCI4.SCR.BIT.RE = 1;   // Enable transmission
	
	// Enable transmission
    SCI4.SCR.BIT.RIE = 0;   // Enable transmission
	SCI4.SCR.BIT.TIE = 0;
	SCI4.SCR.BIT.TEIE = 0;
	SCI4.SCR.BIT.MPIE = 0;
	
	
}

// Function to send a single character via SCI4
void sci4_send_char(char c)
{
	beep(1);
	
    // Wait until the transmit data register is empty
    while (SCI4.SSR.BIT.TDRE == 0);  // Wait for the TDRE flag to be set
	
	beep(5);

    // Write the character to the transmit data register
    SCI4.TDR = c;

    // Clear the TDRE flag by writing 0
    SCI4.SSR.BIT.TDRE = 0;
}

// Function to send a string via SCI4
void sci4_send_string(const char *str)
{
    while (*str) {
        sci4_send_char(*str);  // Send each character in the string
        str++;  // Move to the next character
    }
}

void beep(unsigned int amount)
{
        for (i = 0; i < amount; i++) {
			PC.DR.BIT.B6 = 1;    // Set PC6 high (turn on buzzer)
			delay_ms(500);
			PC.DR.BIT.B6 = 0;
			delay_ms(500);
        }
		
		delay_ms(2000);
}

// Function to create a delay (in milliseconds)
void delay_ms(unsigned long ms)
{
    unsigned long i;
    while (ms--) {
        for (i = 0; i < 5000; i++) {
			nop();
        }
    }
}

#ifdef __cplusplus
void abort(void)
{

}
#endif
 ```

During test and trial I learned how to use the builtin simulator. This is quite the treasure: clear insight in the memory region.
The possibility to step through the assembly and see the original C-code interleaved. 
This is a real help for my next step...

<img src="Images/HEW_debugger.png" alt="AOP Front" title="AOP Front" width="800"/>

# Step 1: Reverse engineering the micro-kernel of the H8S/2633
Well, lets take it easy and first try to 'Reverse engineer' our previously written program.
For which we already have the source code.

First we need the binary of our program that we would flash to the chip. When building the program it creates'.mot' file.
This seems to be a Motorola S-record file. This is the textbased version of the raw binary we would want to flash. 
We could extract the real binary for the serial traffic when programming or we just use a simple program that does the conversion.
I used MOT2BIN.exe, I included it in the repo.

Now that we have got I bin-file we can put it into a dissasembler. I tried loading it with Ghidra
but soon it became clear that Ghidra does not have a dissasembler for this microcontroller's instruction set...

Adding the whole instructionset myself would certainly be some work. Fortunately IDA pro does.
I start IDA pro 32-bit and select my setbuzz.bin file. 
I suggests decompiling it as a COFF-file but I go with raw binary since that is what it is.
As a processor it settles with 'MetaPC' which I guess is the default, but this doesn't work.
Fortunately we have the 'Hitachi H8S advanced' and 'Hitachi H8S normal'. 

<img src="Images/IDA_processors.png" alt="AOP Front" title="AOP Front" width="800"/>

What I recall is the in advanced mode the chip uses a bigger address space. I programmed for advanced so 
lets go with that and hit ok. We get presented with:

<img src="Images/setbuzz_binary_ida.png" alt="AOP Front" title="AOP Front" width="800"/>

Offcourse no functions are found and no assembly codes can be seen because IDA doesn't know
where the program starts and thus where to start to dissasemble. We can start it from a certain address
by going to the address and pressing 'C'(ode). 

Let's take a peek in HEW where our main function start and lets disssable from this address:

<img src="Images/HEW_main_setbuzz.png" alt="AOP Front" title="AOP Front" width="800"/>

<img src="Images/IDA_setbuzz_main.png" alt="AOP Front" title="AOP Front" width="800"/>

We hit 'C' on address '0xA8A' and IDA starts dissasembly from there and is able to find 5 functions.
In the picture above we see three addresses marked in red. This means they point to some memory that is not defined. 

The first address in IDA is '0xFFFFFE38'. While in HEW we see that the address is actually
'0x00FFFE3B' which is the address of 'PC.DDR'. In the manual however we see PC.DDR is 0xFE3B, a bit confusing no? 

<img src="Images/PCDDR.png" alt="AOP Front" title="AOP Front" width="800"/>

Well actually PC.DDR is at 0xFE3B when the CPU is in normal mode, then it uses 16-bit addresses.
in advanced mode it does however use 24-bit address mode making this register available at '0x00FFFE3B'.
However I guess even though we selected the advanced processor I assume IDA only works with either 32-bit addresses or 16bit.
(24 is quite uncommon I'd say).

How do we solve this? Well we can actually tell IDA what segments there are in the chip.
Which for us is:

<img src="Images/memory_map.png" alt="AOP Front" title="AOP Front" width="800"/>

And then for each internal IO-register we can tell it at what address it lives.
So bassically telling IDA the memory map of the chip. 
Apperently IDA currently has this info for only 2 chips:

<img src="Images/IDA_existing_config.png" alt="AOP Front" title="AOP Front" width="800"/>

Let's give it the info of the H8S/2633 as well. I put ChatGPT to work once more and with some help I turn 
10 pages of registers (starting from p1272 from manual) into a nice IDA config file. I replaced the file in 'C:\Program Files\IDA 7.0\cfg\h8.cfg' with my definition of 
the H8S/2633 chip: 

<img src="Images/2633_config.png" alt="AOP Front" title="AOP Front" width="800"/>

When I defined the memory regions IDA apparantly couldn't parse the file but I was able to define
all the registers. After this we can see the registers popup in our dissasembly:

<img src="Images/ida_after_config.png" alt="AOP Front" title="AOP Front" width="800"/>

Okay now lets take a look at what happens before main. 
from 0x0000 to 0x0400 there are all NOP instructions (accept for some, I cannot explain).
So assuming code starts running from address 0x0000 it would just flow to 400hex. 

<img src="Images/HEW_400H.png" alt="AOP Front" title="AOP Front" width="800"/>

Actually from seeing the Dissasembly in HEW we could assume that after power is applied 
the code starts running from 0x400 (_PowerON_Reset). 

Then we see it jumps to __INITSCT (0x408) and __INIT_IOLIB (0x40C) and _HardwareSetup (0x410)
doing probably full setup of everything. 
A Google search led me to a [Renesas page that explains these steps](https://tool-support.renesas.com/autoupdate/support/onlinehelp/csp/V4.01.00/CS+.chm/Compiler-CCRX.chm/Output/ccrx08c0302y.html
)
Basically __INITSCT sets up variables in RAM, that part is something I'm familiar with since I once wanted to check
how I could [reverse engineer an arduino uno program](https://github.com/Sfeeen/Arduino-ATMEGA328-binary-reversing) and wrote a 'ramextracter.py'.
__INITSCT can be split up into 2 smaller functions. [Info can be found here](https://en-support.renesas.com/knowledgeBase/21268230). But this has probably no value
in our journey here.
__INIT_IOLIB is initialisation if you make use of the 'stdio.h, ios, streambuf, istream, or ostream'.

From 0x422 on we see the interrupt vector table. No interruptcode is defined and that's 
we they all have the value 0x5670 with opcode RTE (ReTurn from Exception). 

Scrolling down we encounter the code of the init routines we just discussed.

## Analysing the microkernel
Let's load the microkernel into IDA. Again it has no entrypoint so we just 'c' from the beginning, after 3 tries it suddenly unravels a big chunk of logic:

<img src="Images/IDA_microkernel.png" alt="AOP Front" title="AOP Front" width="800"/>

After inspecting a bit deeper whe see lots of cmp (compare) instructions:

<img src="Images/IDA_microkernel_cmp.png" alt="AOP Front" title="AOP Front" width="800"/>

The byte from a register is each time compared to values like '0x40', '0x20', '0x21', ...
Well these bits seem a bit familiar to me, remember the inquiry and selection command's from the download proccess?

<img src="Images/inquiry_selection_commands.png" alt="AOP Front" title="AOP Front" width="800"/>

Very good, lets rename to blocks they point to with their 'Command Name'. 0x28 and 0x7F are commands that are
undocumented as far as I can find. 

Let's reverse this piece of firmware from bottom to top: we know this is a structure that accepts commands
over serial, performs and actions and then responds with some data over serial. So when we look for a function that is called a lot we find:
Taking a look at this function brings us to a small subroutine that calls this loop function:
<img src="Images/program_erase_state_transition.png" alt="AOP Front" title="AOP Front" width="800"/>

The addresses referenced are part of the I/O map but aren't replaced by their register name because they 
are addressed in 32-bit. I added them to the IDA.cfg file. Turns out it are SCI2 related register, something I already expected.
Analysing the whole logic step by step learns use that this is the function that transmit bytes over SCI2.
It's parameters are a address in memory to send the data from (er0) and an amount of bytes to send (er1). It returns the sum of each byte transmitted. 
We become:
<img src="Images/transmit_bytes_reversed.png" alt="AOP Front" title="AOP Front" width="800"/>

This first one took some time, but as soon as you get the picture things get a bit easier.
Next I was able to find and rename the function that receives bytes as well. 

Then there was a function that calls these transmit bytes function a several times. 
I called this one 'SCI2_send_packet'. Looking back at the main loop function now we get to see this:

<img src="Images/command_and_transmit.png" alt="AOP Front" title="AOP Front" width="800"/>

All commands set a certain address and a size and call 'send_packet'. This function encapsulates the data that needs to be sent back
with some bytes before it and after it.


The first one and for us the most important one is the 0x40 instruction or ' Transition to program/erase state'.
It didn't come through to me before that this is such an important one so I looked back to the communication
traffic I annotated above and saw that this command is issued before downloading the main kernel. 
However from the FDT-logs we saw 'Device is erasing...' Already before 'micro-Kernal download successful'.
Strange! 

Lets focus some more on this instruction for a bit, all other functions more or less seem to result in the sending of some packet
and loop than back to the beginning. But  this one seems a one-way street.
<img src="Images/instruction_0x40.png" alt="AOP Front" title="AOP Front" width="800"/>

So lets take a look at what comes actually after the this loop function.
When the main-loop is escaped there is actually another function, so my guess this one is performing the erase.
I've called it the 'after_main_loop_maybe_erase' for now. After this it just goes back to the main loop, so I'm expecting
this one actually jumps to another memory region.

<img src="Images/after_main_loop.png" alt="AOP Front" title="AOP Front" width="800"/>

At this point I rebased my program to the start of the internal ram region (0xffb00). Off course I have no real
clue of what address this piece of code would be loaded at but from the documentation it was clear that it get's loaded in RAM
Their are 2 regions of RAM (0x00ffb000 - 0x00ffefbf) and (0x00ffffc0 - 0x00ffffff). I took a guess for the first one
and the beginning of the RAM because that would be the most obvious location to put it, right?
Also while reversing I encountered a few unresolved addressed which were 0xFFxxxx (so in the first memory region).

Then I decided to first name all my function because there are only a dozen or so. I ended up with:
<img src="Images/naming_ida_functions.png" alt="AOP Front" title="AOP Front" width="800"/>

Now appart from the code that is translated into assembly instructions there is also a piece at the end of the file
that didn't got translated into code. Looking at this data we see random bytes but also something that seems to to be a string
more specific a product code. 

<img src="Images/variables_in_microkernel.png" alt="AOP Front" title="AOP Front" width="800"/>

If we look back at the annotated communication we see that there is a 'selection of device'. and in the
response we also see the string '0203'. This is the 0x10 instruction. 

<img src="Images/device_selection.png" alt="AOP Front" title="AOP Front" width="800"/>

Taking a look at this code for this function: 

<img src="Images/after_0x10.png" alt="AOP Front" title="AOP Front" width="800"/>

We can see it makes use of address 0x0FFC705. From the picture above we see that 0x0FFB705 points to the value '0x2'.
Probably meaning this microkernel is for 2 devices. Then byte '0xD' follows which it the length of the product string that follows:
'0203HD64F2633' after this the second length byte and the other devicename (0204HD64F2643).

Conclusion: this code is probably loaded at 0xFFC00 instead of 0xFFB00. Let's rebase it again.
Now the 'send_ffc795_byte' function makes also more sence. I was able to name it 'send_ACK' now because of where it occured and comparing it with the recorded
communication flow but now that the addressing is changed I find that 0xFFC795 points to 0x6. Which is indeed the byte value
used for an acknowledgment. Another confirm that our memory is loaded at 0xffc00. This and more pieces
are falling together now. The data after the code section seems like all the global defined variables.

<img src="Images/ack.png" alt="AOP Front" title="AOP Front" width="800"/>

I decided to note which commands all get handled in this microkernel: 
0x40, 0x20, 0x10, 0x21, 0x11, 0x22, 0x3F, 0x25, 0x26, 0x28, 0x23, 0x27, 0x7F, 0x4F

Now looking further at the 'after_main_loop_maybe_erase'-function we get to see this:

<img src="Images/after_main_loop_maybe_erase.png" alt="AOP Front" title="AOP Front" width="800"/>

It seems  to receive some bytes over SCI, sends and 'ACK' but no instruction loop that could
erase a memory region unfortunately...
According to some condition it does jump to 0xffc800.
Our microkernel lives at ffc00 - ffc975 so that would be right behind this.
Probably this just hands over code execution to the main-kernel. It's unclear of how the erase 
gets performed, I can't get my head around it. 

But I have another intermezzo in mind. I want to play and fuzz with this command system so 
I started making a gui to send certain instructions: 

<img src="Images/command_gui.png" alt="AOP Front" title="AOP Front" width="800"/>

I aborted the GUI development halfway because I didn't see a lot of gain in sending commands by buttons 
then by changing my code...

Looking further into this project I decided to try making a first patch to the microkernel 
and hoping to see some effect. I decided to start with a small change: changing the size of the data that gets 
spit out over SCI2. In this piece below I changed the opcode 'F002' to 'F0FF' so it would 
instead of spitting out 2 bytes (surrounded with some other bytes), spit out 0xFF bytes instead.
I saved the patch and used my python programmer to load the kernel and see what happens when the programming
unit inquiry was send. 

<img src="Images/experiment_path_micro_kernel.png" alt="AOP Front" title="AOP Front" width="800"/>

But unfortunately there was no difference.
I checked if what I communicated whas indeed the patched kernel by using IO ninja but it was.
My idea behind this patch was that if this works I could path this kernel so it spits out all memory of the chip
but for now it seems not to work for some reason. This got me doubting if I'm actually
interacting with this code when or for some reason with another piece of code (mask rom) that has similar instruction commands...

I decided to focus some more on the code of the erase state transition (0x40).

<img src="Images/after_main_reversed.png" alt="AOP Front" title="AOP Front" width="800"/>

I learnt it does the following:
- Receive 4 bytes
- Receive a chuck of bytes
- Receive 1 byte

Now, again keeping the communication I saw in IO-ninja in mind, I understood that this is the logic
that receives the main-kernel. The first 4 bytes are the length of the main kernel. Then follows the kernel data
and after that 1 byte, maybe a checksum.

This explains also why I thought that my communicated main-kernel was different from the file
(Genm2633.cde) that was mentioned in the software as kernel. I compared them and they didn't match, but it's just
because I saved the length bytes and the checksum bytes with it. The microkernel got transmitted differently
because the size gets corresponded and acknowledged before sending the file.

I checked the checksum of the file in Hxd: 'D3' but it doesn't match the value transmitted 'A1'.
this doesn't matter that much right now, actually looking further at the kernelcode we can see
that the main kernel will get loaded at 0xFFC800 and it will jump to this code afterwards.
Pretty predictable actually because of the Command Name: I recite: 'Transition to program/erase state'

The description of this command is:
'Erasing of user boot MAT and the user MAT, and entry to programming/erasing state'.
But regarding the 'Erasing' aspect of this command, nothing confirming this can be seen in the code...

Maybe the erase happens at the beginning of the main-kernel then?
Since we now now were it gets loaded I can add it into IDA and decompile this one as well.
I struggled a bit adding a new segment and loading a new piece of data into this project while still having the addressing 
as I wanted so I actually ended up making a merged file that combineds both kernel with some padding bytes and then loaded this one
in a new project and based it at address 0xffc00.
Exporting the function names I already reversed didn't go well so there I also just manually 
renamed the function to the same name. 

Now again we follow the same process of hitting 'c' on segments of the main kernel and we get the 
functions of the main-kernel. 

<img src="Images/ida_both_kernels.png" alt="AOP Front" title="AOP Front" width="800"/>

It's actually pretty similar to the microkernelcode. It also has this loop function that checks what command is received.
I listed the commands this kernel can handle:
- 0x4F boot program status inquiry
- 0x4B usermat at sum check
- 0x48 erase selection
- 0x43 user mat programming selection
- 0x52 memory read
- 0x4d user mat blank check

I renamed some functions in the main_kernel and then took a look at the beginning of this main kernel.
Maybe the erase happens before  the starting of the loop? Wellno, it doesn't seem so:
<img src="Images/main_kernel_entrypoint.png" alt="AOP Front" title="AOP Front" width="800"/>

I decided to take a look from 'to other side', being the software that already interracts with 
the chip and clearly seems to know when the erasing is happening and when it is done...
<img src="Images/fdt_erase.png" alt="AOP Front" title="AOP Front" width="800"/>

I 'wingrepped' the softwarefolder for the sentences 'Device is erasing...' and 'Erase Successfull'

<img src="Images/wingrepping.png" alt="AOP Front" title="AOP Front" width="800"/>

2 hits! the 'FDTApiExt(res).dll' do contain these strings! I loaded these dll's into IDA but couldn't find where these strings are located. 
From experience I know that Wingrep searches more advanced for strings then IDA or cntr+f in notepad. Especially UTF-16 formatted strings
doesn't seem to be found be the latter two. I quickly got annoyed and aborted this path. 

Maybe there is some manual of FDT that would lead to more info? 
Taking a look I stumbled on the 'Renesas FLASH Development Toolkit 4.09 User's Manual'...

The only chapter that could have some relevant info is Chapter 3, 3.2 more specific.
First of all in explains the "Protocol B, C, D and E", A selection I had to make in the beginning when setting up
a project and I had no idea what these meant. 
Then I was reading a section talking about Boot mode and User mode and it talks about a file named 'gentest.h'.

<img src="Images/gentest_h.png" alt="AOP Front" title="AOP Front" width="800"/>

I found this file in the same folder as I found the micro-kernel and the main-kernel... but then... 
did you spot it yet? 
Yes, the source code for both the micro-kernel and main-kernel were actually always right there, next to the compiled kernel code is the header file and the C-file
that make up that code. How could I have not seen this before, when I copied the kernels from this folder?

<img src="Images/kernel_map.png" alt="AOP Front" title="AOP Front" width="800"/>

Probably because I simply did not expect that they want to share the source code for this, but now looking
back to the content of the FDT-pdf is seems like they even want to help users compile their own kernel

'3.2.7 - How do I recompile a kernel'...

<img src="Images/ftd_manual.png" alt="AOP Front" title="AOP Front" width="800"/>

It felt like a nice discovery with a touch of 'feeling stupid' not having seen this the whole time.
It has cost me hours reversing those two kernels in IDA but I didn't regret it. It taught me things I didn't know
and was an acceptable challenge starting in Firmware reversing.

That said let's take a look at the original code now!
First 'Gentest.h', the file mentioned.

<img src="Images/ram_start_address.png" alt="AOP Front" title="AOP Front" width="800"/>

Okay this one reveals the entry point of the main kernel.
Now 'Ugen.c', microkernelcode:

<img src="Images/ugendotc.png" alt="AOP Front" title="AOP Front" width="800"/>
<img src="Images/ugendotc2.png" alt="AOP Front" title="AOP Front" width="800"/>

Okay, seeing this mainly satisfies me with confirmation of how I assumed the code was working.
We indeed see the command switch structure... We see the Get function (SCI_receive_bytes) returns a add_sum so a
kind of checksum indeed. 

Gentest.c actually contains some SCI init function and off course I did also find the functions to send and receive serial
so that should help me if I want to talk over serial furtheron because I couldn't get it working... :')

<img src="Images/gentest_c.png" alt="AOP Front" title="AOP Front" width="800"/>

Looking at the source code from both kernels, indeed the erase function that automatically erases user data
is not there. 
Looking further at other files in this folder e.g. 'KDevice.h' we see FUNC_START, code located at 0xFFC000
with the command 'Write/Erase function start position'. This is actually just the micro-kernel, so no erase there.

<img src="Images/kdevice.png" alt="AOP Front" title="AOP Front" width="800"/>

FDT_erase.c shows some EraseFlASH function that is the FDT entry point. I don't think this is  the exact source code of the erase function we are searching for but it might have similarities.

<img src="Images/FDT_erase_c.png" alt="AOP Front" title="AOP Front" width="800"/>

Okay that's most of the interesting stuff in this folder now. Let's rephrase what my current assumption is:
The MASK rom of the chips contains some code including a part that erases the user's flash region. 
This piece of code, when in boot mode, gets loaded into RAM somewhere at 0xFFB000 - 0xFFC000.
Another piece of code is, what I will call a pre-micro-kernel. Code that gets loaded at the very start of RAM (0xFFB000) 
and handles the acception of the micro-kernel. It plays its part in the bit-rate matching. Then accepts the 
size commands of the kernel and  then the kernel itself. But after writing this kernel to 0xFFC000, before handing execution over to this kernel
it first calls the wipe all flash function and the gives execution to the micro-kernel.

Be aware that this is just my current assumption, and similar to my previous ones it might be subject to future changes.
Though I'm really thinking I'm getting it right now.

Good, what about our plan of attack now, since we don't have assembly to look at now?
Glad you asked! Let's dump the content of the chip from within the micro-kernel.
Okay the ROM section will be already wiped but the pre-micro-kernel code will probably still be in RAM.

I didn't want to compile my own kernel, because it actually seems harder to change the sourcecode
at this point and get it to properly compile then to path the assembly. 
As for why the previous patches I made didn't work: I got it cleared out.
I simply patched the size-byte of the wrong command action. In the graph I stupidly 
followed the wrong arrow for the inquiry I wanted to path resulting in me patching the 
size of bytes that get returned for when you send an INVALID command. Eventually while 
fiddling I decided to send it some faulty instruction suddenly resulting in the bigger readout I was expecting the whole time.
Good, but now I do know my patched code does really run and my patches do what I expect them to do.

My main issue right now is finding an easy patch to dump the whole chip content without
having to make to many changes or changing the size of the kernel bytes.
I could set the start address of a function to 0x00000000 but the size to spit out is only put in a byte-variable
so I would have to perform this an enormous amount of time...

[Taking a walk and thinking about a good patch]

Having a walk did great, and yes, while being outside I got the greatest idea:
lets just patch the SCI_TRANSMIT_BYTE function start from address zero, increment by one and loop endlessly
As soon as this function will be called it will start to dump its entire memory and beyond (would eventually loop over).
I was able to pull it of with only 2 instructions patched, as seen below:

<img src="Images/microkernel_patch.png" alt="AOP Front" title="AOP Front" width="800"/>

It was already after bed-time but I had to try it. And ooh yess, this worked!
it kept spitout out bytes like it had nothing else to do! 

I quickly wrote some lines of python that would accept each bytes and carefully append it to a binfile: 
<img src="Images/python_accept_dump.png" alt="AOP Front" title="AOP Front" width="800"/>

It is kind of slow though and I kept staring at it for a bit, but some simple maths learns me that
was going to take hours so I keep my pc running and get some sleep!

[The day after]

First thing in the morning,  checking my program it was still running perfect! I stopped it and saw it had created a bin-file the size
of a small 32Mbyte so it was really slow dumping but it's enough to cover the advanced mode memory region almost twice
(24-bit addressing = 16Mbyte).

Scrolling over it's content in my hex editor I noted where, what kind of data was found:

- 0x000000 - 0x040000: 0xFF
- 0x040000 - 0xFFB000: 38 8B 38 8B (8<8<) pattern
- 0xFFB000 - 0xFFEFC0: code
- 0xFFEFC0 - 0xFFFDAB: 38 8B 38 8B (8<8<) pattern
- 0xFFFDAB - 0xFFFFFF: some weird data

For the 'weir data', this it what it looks like:

<img src="Images/weird_data.png" alt="AOP Front" title="AOP Front" width="800"/>

I cannot make out what kind of data this is!

Now mapping our findings on the known parts of the memory map we get:

translated to the memory regions:
- 0x000000 - 0x03FFFF (ROM) -> 0xFF
- 0x040000 - 0xFFAFFF (EXT) -> 0xFF
- 0xFFB000 - 0xFFEFBF (RAM) -> code
- 0xFFEFC0 - 0xFFF7FF (EXT) -> (0x38 0x8B) pattern
- 0xFFF800 - 0xFFFF3F (I/O) -> (0x38 0x8B) and some weird data
- 0xFFFF40 - 0xFFFF5F (EXT) -> 38 8B 38 8B (8<8<) pattern
- 0xFFFF60 - 0xFFFFBF (I/O) -> weird data
- 0xFFFFC0 - 0xFFFFFF (RAM) -> weird data

Okay looking at it now its maybe somewhat more explainable. I could understand that the I/O registers
have a kind off repeating though somewhat changing values.
For the second RAM section I have no idea, I don't understand why there are even 2 RAM parts.
Nonetheless I just extracted the first RAM porten and put it into IDA. 

## Reversing the pre-micro-kernel

Reversing this kernel is nothing like the other two. When hitting 'C' it only transforms several lines into code
and then mostly follows a byte or two that cannot be transformed into code, after this again a small portion of code can be formed...
This one is clearly going to be a bit thougher. I also won't find much info about this code from manuals or certainly would find source code for this (Or would I ?).

<img src="Images/premicrokernel.png" alt="AOP Front" title="AOP Front" width="800"/>


The parts that get transformed to code are certainly code I figured because they aren't some exotic opcodes you would find from
forcing data bytes into code. 















