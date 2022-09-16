#!/bin/bash
#
# Author :
# Date : 221001
# Version : 0.0.1
# User Variables :
###############################################################################

BOOTVER="0.0.1"

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

function getstaticmodule() {
    redpillextension="https://github.com/pocopico/rp-ext/raw/main/redpill/rpext-index.json"
    SYNOMODEL="$(echo $model | sed -e 's/+/p/g' | tr '[:upper:]' '[:lower:]')_42218"

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

function patchramdisk() {

    temprd="/root/rd.temp/"
    RAMDISK_PATCH=$(cat /root/config/$model/$version/config.json | jq -r -e ' .patches .ramdisk')
    SYNOINFO_PATCH=$(cat /root/config/$model/$version/config.json | jq -r -e ' .synoinfo')
    SYNOINFO_USER=$(cat /mnt/tcrp/user_config.json | jq -r -e ' .synoinfo')
    RAMDISK_COPY=$(cat /root/config/$model/$version/config.json | jq -r -e ' .extra .ramdisk_copy')
    RD_COMPRESSED=$(cat /root/config/$model/$version/config.json | jq -r -e ' .extra .compress_rd')
    echo "Patching RamDisk"
    echo "Extracting ramdisk to $temprd"

    [ ! -d $temprd ] && mkdir $temprd
    cd $temprd

    if [ $(od /mnt/tcrp-p2/rd.gz | head -1 | awk '{print $2}') == "000135" ]; then
        unlzma -dc /mnt/tcrp-p2/rd.gz | cpio -idm >/dev/null 2>&1
    else
        sudo cat /mnt/tcrp-p2/rd.gz | cpio -idm 2>&1 >/dev/null
    fi

    if [ -f $temprd/etc/VERSION ]; then
        . $temprd/etc/VERSION
        echo "Extracted ramdisk VERSION : ${major}.${minor}.${micro}_${buildnumber}"
    else
        echo "ERROR, Couldnt read extracted file version"
        exit 99
    fi

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
        echo "_set_conf_kv ${KEY} ${VALUE} /tmpRoot/etc/synoinfo.conf'" >>"/root/rp.txt"
        echo "_set_conf_kv ${KEY} ${VALUE} /tmpRoot/etc.defaults/synoinfo.conf'" >>"/root/rp.txt"
    done <<<$(echo $SYNOINFO_PATCH | jq . | grep ":" | sed -e 's/"//g' | sed -e 's/,//g')

    echo "Applying user synoinfo settings"

    while IFS=":" read KEY VALUE; do
        echo "Key : $KEY Value: $VALUE"
        _set_conf_kv $KEY $VALUE $temprd/etc/synoinfo.conf
        echo "_set_conf_kv ${KEY} ${VALUE} /tmpRoot/etc/synoinfo.conf'" >>"/root/rp.txt"
        echo "_set_conf_kv ${KEY} ${VALUE} /tmpRoot/etc.defaults/synoinfo.conf'" >>"/root/rp.txt"
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
    cat /mnt/tcrp-p1/custom.gz | cpio -idm

    for script in $(find /root/rd.temp/exts/ | grep ".sh"); do chmod +x $script; done

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
    cd /root && rm -rf $temprd

    origrdhash=$(sha256sum /mnt/tcrp-p2/rd.gz | awk '{print $1}')
    origzimghash=$(sha256sum /mnt/tcrp-p2/zImage | awk '{print $1}')

    updateuserconfigfield "general" "rdhash" "$origrdhash"
    updateuserconfigfield "general" "zimghash" "$origzimghash"
    updateuserconfigfield "general" "version" "${major}.${minor}.${micro}-${buildnumber}"

}

function updateuserconfig() {

    echo "Checking user config for general block"
    generalblock="$(jq -r -e '.general' $userconfigfile)"
    if [ "$generalblock" = "null" ] || [ -n "$generalblock" ]; then
        echo "Result=${generalblock}, File does not contain general block, adding block"

        for field in model version zimghash rdhash usb_line sata_line; do
            jsonfile=$(jq ".general+={\"$field\":\"\"}" $userconfigfile)
            echo $jsonfile | jq . >$userconfigfile
        done
    fi
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
        let timeout=$timeout-1

        printf '\e[32m%s\e[0m\r' "Press <ctrl-c> to stop booting in : $timeout"
    done

}

function gethw() {

    checkmachine
    printf '\e[32m%s\e[0m' "IP ADDRESS : "

}

function checkmachine() {

    if grep -q ^flags.*\ hypervisor\  /proc/cpuinfo; then
        MACHINE="VIRTUAL"
        HYPERVISOR=$(lscpu | grep "Hypervisor vendor" | awk '{print $3}')
        echo "Machine is $MACHINE and the Hypervisor is $HYPERVISOR"
    fi

}

function getusb() {

    checkmachine

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

    # Wait for an IP
    COUNT=0
    while true; do
        if [ ${COUNT} -eq 20 ]; then
            echo "ERROR"
            break
        fi
        COUNT=$((${COUNT} + 1))
        IP=$(ip route get 1.1.1.1 2>/dev/null | grep dev | awk '{print $7}')
        if [ -n "${IP}" ]; then
            break
        fi
        sleep 1
    done

}

checkupgrade() {

    origrdhash=$(sha256sum /mnt/tcrp-p2/rd.gz | awk '{print $1}')
    origzimghash=$(sha256sum /mnt/tcrp-p2/zImage | awk '{print $1}')
    rdhash="$(jq -r -e '.general .rdhash' $userconfigfile)"
    zimghash="$(jq -r -e '.general .zimghash' $userconfigfile)"

    if [ "$rdhash" = "$origrdhash" ]; then
        echo "Ramdisk OK ! "
    else
        echo "Ramdisk upgrade has been detected "
        patchramdisk
    fi

    if [ "$zimghash" = "$origzimghash" ]; then
        echo "zImage OK ! "
    else
        echo "zImage upgrade has been detected "
        patchkernel
    fi

}

setmac() {

    # Set custom MAC if defined

    ethdev=$(ip route get 1.1.1.1 | awk '{print $5}')
    curmac=$(ip link | grep -A 1 eno33555200 | tail -1 | awk '{print $2}' | sed -e 's/://g' | tr '[:lower:]' '[:upper:]')

    if [ -n "${mac1}" ] && [ "${curmac}" != "${mac1}" ]; then
        MAC="${mac1:0:2}:${mac1:2:2}:${mac1:4:2}:${mac1:6:2}:${mac1:8:2}:${mac1:10:2}"
        echo "Setting MAC to ${MAC}"
        ip link set dev $ethdev address ${MAC} >/dev/null 2>&1 &&
            (/etc/init.d/S41dhcpcd restart >/dev/null 2>&1 &) || true
    fi

    ipaddress=$(ip route get 1.1.1.1 2>/dev/null | awk '{print$7}')

}

readconfig() {

    userconfigfile=/mnt/tcrp/user_config.json

    model="$(jq -r -e '.general .model' $userconfigfile)"
    version="$(jq -r -e '.general .version' $userconfigfile)"
    serial="$(jq -r -e '.extra_cmdline .sn' $userconfigfile)"
    rdhash="$(jq -r -e '.general .rdhash' $userconfigfile)"
    zimghash="$(jq -r -e '.general .zimghash' $userconfigfile)"
    mac1="$(jq -r -e '.extra_cmdline .mac1' $userconfigfile)"

    LOADER_DISK=$(fdisk -l | grep -v raid | grep -v W95 | grep Linux | grep 48M | cut -c 1-8 | awk -F\/ '{print $3}')
    LOADER_BUS="$(udevadm info --query property --name /dev/${LOADER_DISK} | grep -i ID_BUS | awk -F= '{print $2}')"

}

mountall() {

    LOADER_DISK=$(fdisk -l | grep -v raid | grep -v W95 | grep Linux | grep 48M | cut -c 1-8 | awk -F\/ '{print $3}')

    [ ! -d /mnt/tcrp ] && mkdir /mnt/tcrp
    [ ! -d /mnt/tcrp-p1 ] && mkdir /mnt/tcrp-p1
    [ ! -d /mnt/tcrp-p2 ] && mkdir /mnt/tcrp-p2

    [ "$(df | grep ${LOADER_DISK}1 | wc -l)" = "0" ] && mount /dev/${LOADER_DISK}1 /mnt/tcrp-p1
    [ "$(df | grep ${LOADER_DISK}2 | wc -l)" = "0" ] && mount /dev/${LOADER_DISK}2 /mnt/tcrp-p2
    [ "$(df | grep ${LOADER_DISK}3 | wc -l)" = "0" ] && mount /dev/${LOADER_DISK}3 /mnt/tcrp

}

function boot() {

    if [ "$LOADER_BUS" = "ata" ]; then
        CMDLINE_LINE=$(jq -r -e '.general .sata_line' /mnt/tcrp/user_config.json)
    else
        CMDLINE_LINE=$(jq -r -e '.general .usb_line' /mnt/tcrp/user_config.json)
    fi

    export MOD_ZIMAGE_FILE="/mnt/tcrp/zImage-dsm"
    export MOD_RDGZ_FILE="/mnt/tcrp/initrd-dsm"

    echo "IP Address : ${ipaddress}"
    echo "Model : $model , Serial : $serial, Mac : $mac1"
    echo "Loader BUS: $LOADER_BUS "
    echo "zImage : ${MOD_ZIMAGE_FILE} initrd : ${MOD_RDGZ_FILE}"
    echo "cmdline : ${CMDLINE_LINE}"

    countdown

    echo "Boot timeout exceeded, booting ... "

    echo "Loading kexec..."

    kexec --noefi -l "${MOD_ZIMAGE_FILE}" --initrd "${MOD_RDGZ_FILE}" --command-line="${CMDLINE_LINE}"

    kexec -e -a

}

function initialize() {
    # Mount loader disk
    mountall

    # Read Configuration variables
    readconfig

    # Check ip upgrade is required
    checkupgrade

    # Set Mac Address according to user_config
    setmac

    # Get IP Address after setting new mac address to display IP
    getip

    # Get USB list and set VID-PID Automatically
    getusb
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

*)
    initialize
    # All done, lets go for boot/
    boot
    ;;

esac
