#!/bin/bash
#
# Author :
# Date : 221001
# Version : 0.0.1
# User Variables :
###############################################################################

BOOTVER="0.0.1"
FRIENDLOG="/mnt/tcrp/friendlog.log"
RSS_SERVER="https://raw.githubusercontent.com/pocopico/redpill-load/develop"
AUTOUPDATES="1"

###############################################################################

function version() {
    shift 1
    echo $BOOTVER
    [ "$1" == "history" ] && history
}

function history() {
    cat <<EOF
    --------------------------------------------------------------------------------------
    0.0.1 Initial Release
    --------------------------------------------------------------------------------------
EOF
}

function msgalert() {
    echo -en "\033[1;31m$1\033[0m"
}
function msgwarning() {
    echo -en "\033[1;33m$1\033[0m"
}
function msgnormal() {
    echo -en "\033[1;32m$1\033[0m"
}

function upgradefriend() {

    if [ ! -z "$IP" ]; then

        echo -n "Checking for latest friend -> "
        URL=$(curl --connect-timeout 15 -s --insecure -L https://api.github.com/repos/pocopico/tcrpfriend/releases/latest | jq -r -e .assets[].browser_download_url | grep chksum)
        curl -s --insecure -L $URL -O

        if [ -f chksum ]; then
            FRIENDVERSION="$(grep VERSION chksum | awk -F= '{print $2}')"
            BZIMAGESHA256="$(grep bzImage-friend chksum | awk '{print $1}')"
            INITRDSHA256="$(grep initrd-friend chksum | awk '{print $1}')"
            if [ "$(sha256sum /mnt/tcrp/bzImage-friend | awk '{print $1}')" = "$BZIMAGESHA256" ] && [ "$(sha256sum /mnt/tcrp/initrd-friend | awk '{print $1}')" = "$INITRDSHA256" ]; then
                msgnormal "OK, latest \n"
            else
                msgwarning "Found new version, bringing over new friend version : $FRIENDVERSION \n"
                URLS=$(curl --insecure -s https://api.github.com/repos/pocopico/tcrpfriend/releases/latest | jq -r ".assets[].browser_download_url")
                for file in $URLS; do curl --insecure --location --progress-bar "$file" -O; done
                FRIENDVERSION="$(grep VERSION chksum | awk -F= '{print $2}')"
                BZIMAGESHA256="$(grep bzImage-friend chksum | awk '{print $1}')"
                INITRDSHA256="$(grep initrd-friend chksum | awk '{print $1}')"
                [ "$(sha256sum bzImage-friend | awk '{print $1}')" = "$BZIMAGESHA256" ] && [ "$(sha256sum initrd-friend | awk '{print $1}')" = "$INITRDSHA256" ] && cp -f bzImage-friend /mnt/tcrp/ && msgnormal "bzImage OK! \n"
                [ "$(sha256sum bzImage-friend | awk '{print $1}')" = "$BZIMAGESHA256" ] && [ "$(sha256sum initrd-friend | awk '{print $1}')" = "$INITRDSHA256" ] && cp -f initrd-friend /mnt/tcrp/ && msgnormal "initrd-friend OK! \n"
                msgnormal "TCRP FRIEND HAS BEEN UPDATED, GOING FOR REBOOT\n"
                countdown "REBOOT"
                reboot -f
            fi
        else
            msgalert "No IP yet to check for latest friend \n"
        fi
    fi
}

function getstaticmodule() {
    redpillextension="https://github.com/pocopico/rp-ext/raw/main/redpill${redpillmake}/rpext-index.json"
    SYNOMODEL="$(echo $model | sed -e 's/+/p/g' | tr '[:upper:]' '[:lower:]')_${buildnumber}"

    cd /root

    echo "Removing any old redpill.ko modules"
    [ -f /root/redpill.ko ] && rm -f /root/redpill.ko

    extension=$(curl --insecure --silent --location "$redpillextension")

    echo "Looking for redpill for : $SYNOMODEL"

    release=$(echo $extension | jq -r -e --arg SYNOMODEL $SYNOMODEL '.releases[$SYNOMODEL]')
    files=$(curl --insecure --silent --location "$release" | jq -r '.files[] .url')

    for file in $files; do
        echo "Getting file $file"
        curl --insecure --silent -O $file
        if [ -f redpill*.tgz ]; then
            echo "Extracting module"
            gunzip redpill*.tgz
            tar xf redpill*.tar
            rm redpill*.tar
            strip --strip-debug redpill.ko
        fi
    done

    if [ -f /root/redpill.ko ] && [ -n $(strings /root/redpill.ko | grep -i $model) ]; then
        echo "Copying redpill.ko module to ramdisk"
        cp /root/redpill.ko /root/rd.temp/usr/lib/modules/rp.ko
    else
        echo "Module does not contain platorm information for ${model}"
    fi

    [ -f /root/rd.temp/usr/lib/modules/rp.ko ] && echo "Redpill module is in place"

}

function _set_conf_kv() {
    # Delete
    if [ -z "$2" ]; then
        sed -i "$3" -e "s/^$1=.*$//"
        return 0
    fi

    # Replace
    if grep -q "^$1=" "$3"; then
        sed -i "$3" -e "s\"^$1=.*\"$1=\\\"$2\\\"\""
        return 0
    fi

    # Add if doesn't exist
    echo "$1=\"$2\"" >>$3
}

function patchkernel() {

    echo "Patching Kernel"

    /root/tools/bzImage-to-vmlinux.sh /mnt/tcrp-p2/zImage /root/vmlinux >log 2>&1 >/dev/null
    /root/tools/kpatch /root/vmlinux /root/vmlinux-mod >log 2>&1 >/dev/null
    /root/tools/vmlinux-to-bzImage.sh /root/vmlinux-mod /mnt/tcrp/zImage-dsm >/dev/null

    [ -f /mnt/tcrp/zImage-dsm ] && echo "Kernel Patched, sha256sum : $(sha256sum /mnt/tcrp/zImage-dsm | awk '{print $1}')"

}

function extractramdisk() {

    temprd="/root/rd.temp/"

    echo "Extracting ramdisk to $temprd"

    [ ! -d $temprd ] && mkdir $temprd
    cd $temprd

    if [ $(od /mnt/tcrp-p2/rd.gz | head -1 | awk '{print $2}') == "000135" ]; then
        echo "Ramdisk is compressed"
        xz -dc /mnt/tcrp-p2/rd.gz 2>/dev/null | cpio -idm >/dev/null 2>&1
    else
        sudo cat /mnt/tcrp-p2/rd.gz | cpio -idm 2>&1 >/dev/null
    fi

    if [ -f $temprd/etc/VERSION ]; then
        . $temprd/etc/VERSION
        echo "Extracted ramdisk VERSION : ${major}.${minor}.${micro}-${buildnumber}"
    else
        echo "ERROR, Couldnt read extracted file version"
        exit 99
    fi

    version="${major}.${minor}.${micro}-${buildnumber}"

}

function patchramdisk() {

    extractramdisk

    temprd="/root/rd.temp"
    RAMDISK_PATCH=$(cat /root/config/$model/$version/config.json | jq -r -e ' .patches .ramdisk')
    SYNOINFO_PATCH=$(cat /root/config/$model/$version/config.json | jq -r -e ' .synoinfo')
    SYNOINFO_USER=$(cat /mnt/tcrp/user_config.json | jq -r -e ' .synoinfo')
    RAMDISK_COPY=$(cat /root/config/$model/$version/config.json | jq -r -e ' .extra .ramdisk_copy')
    RD_COMPRESSED=$(cat /root/config/$model/$version/config.json | jq -r -e ' .extra .compress_rd')
    echo "Patching RamDisk"

    PATCHES="$(echo $RAMDISK_PATCH | jq . | sed -e 's/@@@COMMON@@@/\/root\/config\/_common/' | grep config | sed -e 's/"//g' | sed -e 's/,//g')"

    echo "Patches to be applied : $PATCHES"

    cd $temprd
    for patch in $PATCHES; do
        echo "Applying patch $patch in dir $PWD"
        patch -p1 <$patch
    done

    # Patch /sbin/init.post
    grep -v -e '^[\t ]*#' -e '^$' "/root/patch/config-manipulators.sh" >"/root/rp.txt"
    sed -e "/@@@CONFIG-MANIPULATORS-TOOLS@@@/ {" -e "r /root/rp.txt" -e 'd' -e '}' -i "${temprd}/sbin/init.post"
    rm "/root/rp.txt"

    touch "/root/rp.txt"

    echo "Applying model synoinfo patches"

    while IFS=":" read KEY VALUE; do
        echo "Key : $KEY Value: $VALUE"
        _set_conf_kv $KEY $VALUE $temprd/etc/synoinfo.conf
        echo "_set_conf_kv ${KEY} ${VALUE} /tmpRoot/etc/synoinfo.conf" >>"/root/rp.txt"
        echo "_set_conf_kv ${KEY} ${VALUE} /tmpRoot/etc.defaults/synoinfo.conf" >>"/root/rp.txt"
    done <<<$(echo $SYNOINFO_PATCH | jq . | grep ":" | sed -e 's/"//g' | sed -e 's/,//g')

    echo "Applying user synoinfo settings"

    while IFS=":" read KEY VALUE; do
        echo "Key : $KEY Value: $VALUE"
        _set_conf_kv $KEY $VALUE $temprd/etc/synoinfo.conf
        echo "_set_conf_kv ${KEY} ${VALUE} /tmpRoot/etc/synoinfo.conf" >>"/root/rp.txt"
        echo "_set_conf_kv ${KEY} ${VALUE} /tmpRoot/etc.defaults/synoinfo.conf" >>"/root/rp.txt"
    done <<<$(echo $SYNOINFO_USER | jq . | grep ":" | sed -e 's/"//g' | sed -e 's/,//g')

    sed -e "/@@@CONFIG-GENERATED@@@/ {" -e "r /root/rp.txt" -e 'd' -e '}' -i "${temprd}/sbin/init.post"
    rm /root/rp.txt

    echo "Copying extra ramdisk files "

    while IFS=":" read SRC DST; do
        echo "Source :$SRC Destination : $DST"
        cp -f $SRC $DST
    done <<<$(echo $RAMDISK_COPY | jq . | grep "COMMON" | sed -e 's/"//g' | sed -e 's/,//g' | sed -e 's/@@@COMMON@@@/\/root\/config\/_common/')

    echo "Adding precompiled redpill module"
    getstaticmodule

    echo "Adding custom.gz to image"
    cd $temprd
    cat /mnt/tcrp-p1/custom.gz | cpio -idm >/dev/null 2>&1

    for script in $(find /root/rd.temp/exts/ | grep ".sh"); do chmod +x $script; done
    chmod +x $temprd/usr/sbin/modprobe

    # Reassembly ramdisk
    echo "Reassempling ramdisk"
    if [ "${RD_COMPRESSED}" == "true" ]; then
        (cd "${temprd}" && find . | cpio -o -H newc -R root:root | xz -9 --format=lzma >"/root/initrd-dsm") >/dev/null 2>&1 >/dev/null
    else
        (cd "${temprd}" && find . | cpio -o -H newc -R root:root >"/root/initrd-dsm") >/dev/null 2>&1
    fi
    [ -f /root/initrd-dsm ] && echo "Patched ramdisk created $(ls -l /root/initrd-dsm)"

    echo "Copying file to ${LOADER_DISK}3"

    cp -f /root/initrd-dsm /mnt/tcrp
    cp -f /root/initrd-dsm /mnt/tcrp-p1/rd.gz
    cd /root && rm -rf $temprd

    origrdhash=$(sha256sum /mnt/tcrp-p2/rd.gz | awk '{print $1}')
    origzimghash=$(sha256sum /mnt/tcrp-p2/zImage | awk '{print $1}')

    updateuserconfigfield "general" "rdhash" "$origrdhash"
    updateuserconfigfield "general" "zimghash" "$origzimghash"
    updateuserconfigfield "general" "version" "${major}.${minor}.${micro}-${buildnumber}"

    version="${major}.${minor}.${micro}-${buildnumber}"

    updategrubconf

}

function updateuserconfig() {

    echo "Checking user config for general block"
    generalblock="$(jq -r -e '.general' $userconfigfile)"
    if [ "$generalblock" = "null" ] || [ -n "$generalblock" ]; then
        echo "Result=${generalblock}, File does not contain general block, adding block"

        for field in model version redpillmake zimghash rdhash usb_line sata_line; do
            jsonfile=$(jq ".general+={\"$field\":\"\"}" $userconfigfile)
            echo $jsonfile | jq . >$userconfigfile
        done
    fi
}

function updategrubconf() {

    curgrubver="$(grep menuentry /mnt/tcrp-p1/boot/grub/grub.cfg | grep RedPill | head -1 | awk '{print $4}')"
    echo "Updating grub version values from: $curgrubver to $version"
    sed -i "s/$curgrubver/$version/g" /mnt/tcrp-p1/boot/grub/grub.cfg

}

function updateuserconfigfield() {

    block="$1"
    field="$2"
    value="$3"

    if [ -n "$1 " ] && [ -n "$2" ]; then
        jsonfile=$(jq ".$block+={\"$field\":\"$value\"}" $userconfigfile)
        echo $jsonfile | jq . >$userconfigfile
    else
        echo "No values to update specified"
    fi
}

function countdown() {

    let timeout=5
    while [ $timeout -ge 0 ]; do
        sleep 1
        printf '\e[32m%s\e[0m\r' "Press <ctrl-c> to stop $1 in : $timeout"
        let timeout=$timeout-1
    done

}

function gethw() {

    checkmachine

    echo -ne "Loader BUS: $(msgnormal "$LOADER_BUS\n")"
    echo -ne "Running on $(cat /proc/cpuinfo | grep "model name" | awk -F: '{print $2}' | wc -l) Processor $(cat /proc/cpuinfo | grep "model name" | awk -F: '{print $2}' | uniq) With $(free -h | grep Mem | awk '{print $2}') Memory\n"
    echo -ne "System has $(lspci -nn | egrep -e "\[0100\]" -e "\[0106\]" | wc -l) HBAs and $(lspci -nn | egrep -e "\[0200\]" | wc -l) Network cards\n"
}

function checkmachine() {

    if grep -q ^flags.*\ hypervisor\  /proc/cpuinfo; then
        MACHINE="VIRTUAL"
        HYPERVISOR=$(lscpu | grep "Hypervisor vendor" | awk '{print $3}')
        echo "Machine is $MACHINE and the Hypervisor is $HYPERVISOR"
    fi

}

function getusb() {

    # Get the VID/PID if we are in USB
    VID="0x0000"
    PID="0x0000"
    BUS=$(udevadm info --query property --name ${LOADER_DISK} | grep BUS | cut -d= -f2)
    if [ "${BUS}" = "usb" ]; then
        VID="0x$(udevadm info --query property --name ${LOADER_DISK} | grep ID_VENDOR_ID | cut -d= -f2)"
        PID="0x$(udevadm info --query property --name ${LOADER_DISK} | grep ID_MODEL_ID | cut -d= -f2)"
        updateuserconfigfield "extra_cmdline" "pid" "$PID"
        updateuserconfigfield "extra_cmdline" "vid" "$VID"
        curpid=$(jq -r -e .general.usb_line $userconfigfile | awk -Fpid= '{print $2}' | awk '{print  $1}')
        curvid=$(jq -r -e .general.usb_line $userconfigfile | awk -Fvid= '{print $2}' | awk '{print  $1}')
        sed -i "s/${curpid}/${PID}/" $userconfigfile
        sed -i "s/${curvid}/${VID}/" $userconfigfile
    elif [ "${BUS}" != "ata" ]; then
        echo "Loader disk neither USB or DoM"
    fi

}

getip() {

    ethdev=$(ip a | grep UP | grep -v LOOP | head -1 | awk '{print $2}' | sed -e 's/://g')

    # Wait for an IP
    COUNT=0
    while true; do
        if [ ${COUNT} -eq 15 ]; then
            msgalert "ERROR Could not get IP\n"
            break
        fi
        COUNT=$((${COUNT} + 1))
        IP="$(ip route get 1.1.1.1 2>/dev/null | grep $ethdev | awk '{print $7}')"
        if [ -n "$IP" ]; then
            break
        fi
        sleep 1
    done

}

checkfiles() {

    files="user_config.json initrd-dsm zImage-dsm"

    for file in $files; do
        if [ -f /mnt/tcrp/$file ]; then
            msgnormal "File : $file OK !"
        else
            msgnormal "File : $file missing  !"
            exit 99
        fi

    done

}

checkupgrade() {

    origrdhash=$(sha256sum /mnt/tcrp-p2/rd.gz | awk '{print $1}')
    origzimghash=$(sha256sum /mnt/tcrp-p2/zImage | awk '{print $1}')
    rdhash="$(jq -r -e '.general .rdhash' $userconfigfile)"
    zimghash="$(jq -r -e '.general .zimghash' $userconfigfile)"

    echo -n "Detecting upgrade : "

    if [ "$rdhash" = "$origrdhash" ]; then
        msgnormal "Ramdisk OK ! "
    else
        msgwarning "Ramdisk upgrade has been detected "
        patchramdisk 2>&1 >>$FRIENDLOG
    fi

    if [ "$zimghash" = "$origzimghash" ]; then
        msgnormal "zImage OK ! \n"
    else
        msgwarning "zImage upgrade has been detected \n"
        patchkernel 2>&1 >>$FRIENDLOG
    fi

}

setmac() {

    # Set custom MAC if defined

    ethdev=$(ip a | grep UP | grep -v LOOP | head -1 | awk '{print $2}' | sed -e 's/://g')
    curmac=$(ip link | grep -A 1 $ethdev | tail -1 | awk '{print $2}' | sed -e 's/://g' | tr '[:lower:]' '[:upper:]')

    if [ -n "${mac1}" ] && [ "${curmac}" != "${mac1}" ]; then
        MAC="${mac1:0:2}:${mac1:2:2}:${mac1:4:2}:${mac1:6:2}:${mac1:8:2}:${mac1:10:2}"
        echo "Setting MAC from ${curmac} to ${MAC}" | tee -a boot.log
        ip link set dev $ethdev address ${MAC} >/dev/null 2>&1 &&
            (/etc/init.d/S41dhcpcd restart >/dev/null 2>&1) || true
    fi

}

readconfig() {

    LOADER_DISK=$(blkid | grep "6234-C863" | cut -c 1-8 | awk -F\/ '{print $3}')
    LOADER_BUS="$(udevadm info --query property --name /dev/${LOADER_DISK} | grep -i ID_BUS | awk -F= '{print $2}')"

    userconfigfile=/mnt/tcrp/user_config.json

    if [ -f $userconfigfile ]; then
        model="$(jq -r -e '.general .model' $userconfigfile)"
        version="$(jq -r -e '.general .version' $userconfigfile)"
        redpillmake="$(jq -r -e '.general .redpillmake' $userconfigfile)"
        serial="$(jq -r -e '.extra_cmdline .sn' $userconfigfile)"
        rdhash="$(jq -r -e '.general .rdhash' $userconfigfile)"
        zimghash="$(jq -r -e '.general .zimghash' $userconfigfile)"
        mac1="$(jq -r -e '.extra_cmdline .mac1' $userconfigfile)"
    else
        echo "ERROR ! User config file : $userconfigfile not found"
    fi

}

mountall() {

    LOADER_DISK=$(blkid | grep "6234-C863" | cut -c 1-8 | awk -F\/ '{print $3}')

    [ ! -d /mnt/tcrp ] && mkdir /mnt/tcrp
    [ ! -d /mnt/tcrp-p1 ] && mkdir /mnt/tcrp-p1
    [ ! -d /mnt/tcrp-p2 ] && mkdir /mnt/tcrp-p2

    [ "$(mount | grep ${LOADER_DISK}1 | wc -l)" = "0" ] && mount /dev/${LOADER_DISK}1 /mnt/tcrp-p1
    [ "$(mount | grep ${LOADER_DISK}2 | wc -l)" = "0" ] && mount /dev/${LOADER_DISK}2 /mnt/tcrp-p2
    [ "$(mount | grep ${LOADER_DISK}3 | wc -l)" = "0" ] && mount /dev/${LOADER_DISK}3 /mnt/tcrp

}

function boot() {

    # Welcome message
    welcome

    # Check ip upgrade is required
    checkupgrade

    # Set Mac Address according to user_config
    setmac

    # Get IP Address after setting new mac address to display IP
    getip

    # Get USB list and set VID-PID Automatically
    getusb

    # check if new TCRP Friend version is available to download
    upgradefriend

    if [ -f /mnt/tcrp/stopatfriend ]; then
        echo "Stop at friend detected, stopping boot"
        rm -f /mnt/tcrp/stopatfriend
        touch /root/stoppedatrequest
        exit 0
    fi

    if grep -q "debugfriend" /proc/cmdline; then
        echo "Debug Friend set, stopping boot process"
        exit 0
    fi

    if [ "$LOADER_BUS" = "ata" ]; then
        CMDLINE_LINE=$(jq -r -e '.general .sata_line' /mnt/tcrp/user_config.json)
    else
        CMDLINE_LINE=$(jq -r -e '.general .usb_line' /mnt/tcrp/user_config.json)
    fi

    [ "$1" = "forcejunior" ] && CMDLINE_LINE+=" force_junior "

    # Check dom size and set max size accordingly

    CMDLINE_LINE+=" dom_szmax=$(fdisk -l /dev/${LOADER_DISK} | head -1 | awk -F: '{print $2}' | awk '{ print $1*1024}') "

    export MOD_ZIMAGE_FILE="/mnt/tcrp/zImage-dsm"
    export MOD_RDGZ_FILE="/mnt/tcrp/initrd-dsm"

    gethw

    echo "IP Address : $(msgnormal "${IP}\n")"
    echo -n "Model : $(msgnormal " $model") , Serial : $(msgnormal "$serial"), Mac : $(msgnormal "$mac1") DSM Version : $(msgnormal "$version") RedPillMake : $(msgnormal "${redpillmake}\n")"

    echo "zImage : ${MOD_ZIMAGE_FILE} initrd : ${MOD_RDGZ_FILE}"
    echo "cmdline : ${CMDLINE_LINE}"

    # Check netif_num matches the number of configured mac addresses as if these does not match redpill will cause a KP
    echo ${CMDLINE_LINE} >/tmp/cmdline.out
    while IFS=" " read -r -a line; do
        printf "%s\n" "${line[@]}"
    done </tmp/cmdline.out | egrep -i "sataportmap|sn|pid|vid|mac|hddhotplug|diskidxmap|netif_num" | sort >/tmp/cmdline.check

    . /tmp/cmdline.check

    [ $(grep mac /tmp/cmdline.check | wc -l) != $netif_num ] && msgalert "FAILED to match the count of configured netif_num and mac addresses, DSM will panic, exiting so you can fix this\n" && exit 99

    countdown "booting"

    echo "Boot timeout exceeded, booting ... "

    echo "Loading kexec, nothing will be displayed here anymore ..."

    if [ $(echo ${CMDLINE_LINE} | grep withefi | wc -l) -eq 1 ]; then
        kexec -l "${MOD_ZIMAGE_FILE}" --initrd "${MOD_RDGZ_FILE}" --command-line="${CMDLINE_LINE}"
    else
        echo "Booting with noefi, please notice that this might cause issues"
        kexec --noefi -l "${MOD_ZIMAGE_FILE}" --initrd "${MOD_RDGZ_FILE}" --command-line="${CMDLINE_LINE}"
    fi

    kexec -e -a

}

function welcome() {

    clear
    echo -en "\033[7;32m---------------------------------={ TinyCore RedPill Friend }=---------------------------------\033[0m\n"

    # Echo Version
    echo "TCRP Friend Version : $BOOTVER"

}

function initialize() {
    # Checkif running in TC
    [ "$(hostname)" != "tcrpfriend" ] && echo "ERROR running on alien system" && exit 99

    # Mount loader disk
    mountall

    # Read Configuration variables
    readconfig

}

case $1 in

patchramdisk)
    initialize
    patchramdisk
    ;;

patchkernel)
    initialize
    patchkernel
    ;;

version)
    version $@
    ;;

extractramdisk)
    initialize
    extractramdisk
    ;;

forcejunior)
    initialize
    boot forcejunior
    ;;

*)
    initialize
    # All done, lets go for boot/
    boot
    ;;

esac
