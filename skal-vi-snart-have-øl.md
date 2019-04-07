# Raretowin

Actually solved this challenge without going down any rabbitholes, mostly due to the fact of my very handy volatility cheatsheet (find it in the cheatsheet folder)

Started off by identifying the OS version with 'volatility -f raretowin.raw imageinfo' and as such got 'Win7SP1x64' as result.

Next step was to look for suspicious or malicious proccesses 'volatility -f raretowin.raw --profile Win7SP1x64 pstree > pstree'.
'''
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xfffffa8002414290:explorer.exe                     1448   1420     33    931 2019-03-23 20:42:39 UTC+0000
. 0xfffffa8002521180:VBoxTray.exe                    1792   1448     13    149 2019-03-23 20:42:39 UTC+0000
. 0xfffffa80007b4060:DumpIt.exe                      2464   1448      2     45 2019-03-23 20:47:45 UTC+0000
 0xfffffa8001743670:chrome.exe                       2912   2756     43   1020 2019-03-23 20:45:11 UTC+0000
. 0xfffffa80024e9060:chrome.exe                      2656   2912      2     58 2019-03-23 20:45:13 UTC+0000
. 0xfffffa8000e5e060:chrome.exe                      2652   2912      9    166 2019-03-23 20:45:23 UTC+0000
. 0xfffffa8000e34060:chrome.exe                      2972   2912     15    233 2019-03-23 20:45:37 UTC+0000
. 0xfffffa8001ae8b30:chrome.exe                      1220   2912      0 ------ 2019-03-23 20:46:22 UTC+0000
. 0xfffffa8000f16060:chrome.exe                      1096   2912     14    174 2019-03-23 20:47:31 UTC+0000
. 0xfffffa80007c5b30:chrome.exe                      2908   2912      0 ------ 2019-03-23 20:46:50 UTC+0000
. 0xfffffa80007bdb30:chrome.exe                      2744   2912      8     86 2019-03-23 20:45:11 UTC+0000
. 0xfffffa8000e712f0:chrome.exe                      2704   2912      0 ------ 2019-03-23 20:46:50 UTC+0000
. 0xfffffa80018d87a0:chrome.exe                      2792   2912      0 ------ 2019-03-23 20:47:12 UTC+0000
. 0xfffffa8000e03060:chrome.exe                      2224   2912     15    177 2019-03-23 20:47:31 UTC+0000
. 0xfffffa80023e3400:chrome.exe                      1248   2912     15    192 2019-03-23 20:46:26 UTC+0000
. 0xfffffa8000e51b30:chrome.exe                      1704   2912      0 ------ 2019-03-23 20:47:08 UTC+0000
. 0xfffffa8000e7b060:chrome.exe                      2740   2912      0 ------ 2019-03-23 20:46:59 UTC+0000
 0xfffffa80006a3670:wininit.exe                       388    332      3     74 2019-03-23 20:42:36 UTC+0000
. 0xfffffa8002046b30:services.exe                     484    388      9    188 2019-03-23 20:42:36 UTC+0000
...
'''

Nothing seemed suspicious, but this did tell me that the user used Chrome and not IE or firefox (!) as browser.

Thus i loaded up superponible plugins to search for chromehistory 'volatility --plugins=../volatility-plugins/ chromehistory -f raretowin.raw --profile Win7SP1x64 > chromehistory'
'''
Index  URL                                                                              Title                                                                            Visits Typed Last Visit Time            Hidden Favicon ID
------ -------------------------------------------------------------------------------- -------------------------------------------------------------------------------- ------ ----- -------------------------- ------ ----------
     5 https://www.google.com/search?ei=E5uWXJ.......1..gws-wiz.......33i10.1d1MmLHudn8 music macklemore & ryan lewis download - بحث Google‏                             1     0 2019-03-23 20:46:19.759382        N/A       
     4 https://www.google.com/search?ei=C5uWXL...-wiz.......0i7i30j0i8i7i30.o2tBk6J7PNY music macklemore & ryan lewis - بحث Google‏                                      1     0 2019-03-23 20:46:14.328534        N/A       
     3 https://www.google.com/search?source=hp....gws-wiz.....0..0i131j0i10.ZF1jOaSrzUQ macklemore & ryan lewis - بحث Google‏                                            1     0 2019-03-23 20:46:06.948223        N/A       
     2 https://www.google.com/                                                          Google                                                                                1     1 2019-03-23 20:45:46.371044        N/A       
     6 https://www.google.tn/_/chro�                                                                                                                         1     1 1601-01-01 00:00:00               N/A       
     9 https://www.mediafire.com/file/2t7bb2mflg2lwwj/music.rar/file#                   music                                                                                 2     0 2019-03-23 20:47:28.109720        N/A       
     8 https://www.mediafire.com/file/2t7bb2mflg2lwwj/music.rar/file#!                  music                                                                                 2     0 2019-03-23 20:46:41.978975        N/A       
     7 https://www.mediafire.com/file/2t7bb2mflg2lwwj/music.rar/file                    music                                                                                 3     0 2019-03-23 20:46:41.978975        N/A       
     6 https://www.google.tn/_/chrome/newtab?ie=UTF-8                                                                                                                         1     1 2019-03-23 20:46:27.270709        N/A       
     1 http://www.google.com/                                                           Google                                                                                1     0 2019-03-23 20:45:46.371044        N/A    
 '''
This revealed only a handful of searches, including some suspicious ones, namely the one from mediafire. I downloaded the rar file in my VM, and immediately saw that this was not a zip.

Using 'strings' on the file i noticed an ELF file within the file, and a suspicious directory within this ELF 'C:\\Users\Public\Data\firefox.exe'

__Flag__
Converting the path to 'C:\\Users\\Public\\Data\\firefox.exe' and taking the MD5 sum of it gives us the flag.
Securinets{9c2623856856ce8aa830a5feb0e4910d}
