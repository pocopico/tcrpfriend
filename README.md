# Welcome to the tcrpfriend, some generic instruction for TCRP Friend.

TCRP Friend boots automatically after including it with your build or bringfriend command.

On the booting countdown you can stop and perform manually a series of actions 

Command: ./boot.sh patchkernel
Description: Patches the kernel

Command: ./boot.sh patchramdisk
Description: Patches the ramdisk

Command: ./boot.sh
Description: Boots the system


Required Files : 

File/Location: /mnt/tcrp
Description: Its the third partition of the loader that holds a number of files required for loader operation. Do not remove files from the loader disk unless you are certain that can be removed.
Files and description : 




 |Filename         |Description |
 |vmlinuz64        |Tinycore Linux kernel            |
 |cde              |Tinycore Linux Packages|
 |corepure64.gz    |Tinycore Linux Ramdisk |
 |lastsession      |TCRP Last session files |
 |backup           |backup files created with ./rploader.sh backuploader|
 |mydata.tgz       |Tinycore Linux user files|
 |auxfiles         |TCRP auxfiles, cache pat files etc|
 |zImage-dsm       |Patched DSM kernel|
 |initrd-dsm       |Patched DSM ramdisk|
 |friendlog.log    |TCRP Friend log|
 |initrd-friend    |TCRP Friend ramdisk|
 |bzImage-friend   |TCRP Friend kernel            |
 |user_config.json |TCRP Friend and TCRP user_config.json, contains user configuration keys |


