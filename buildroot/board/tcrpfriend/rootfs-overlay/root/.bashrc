# ~/.bashrc: executed by bash(1) for non-login shells.

# Note: PS1 and umask are already set in /etc/profile. You should not
# need this unless you want different defaults for root.
PS1='\u@\h:\w# '
# umask 022

# You may uncomment the following lines if you want `ls' to be colorized:
export LS_OPTIONS='--color=auto'
alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -l'
# Special aliases for DSM troubleshooting
alias xrd='mkdir -p /root/rd && cd /root/rd && cat /mnt/tcrp/initrd-dsm|cpio -idm'
alias crd='cd /root/rd && find . | cpio -o -H newc -R root:root >/mnt/tcrp/initrd-dsm'
alias xcs='mkdir -p /root/cs && cd /root/cs && cat /mnt/tcrp/custom.gz |cpio -idm'
alias ccs='cd /root/cs && find . | cpio -o -H newc -R root:root >/mnt/tcrp/custom.gz'
alias prm='cd /root && ./boot.sh patchramdisk'
alias pkn='cd /root && ./boot.sh patchkernel'




# Save history in realtime
shopt -s histappend
PROMPT_COMMAND="history -a;$PROMPT_COMMAND"

export EDITOR="/bin/nano"
export BOOTLOADER_PATH="/mnt/p1"
export SLPART_PATH="/mnt/p2"  # Synologic partition
export CACHE_PATH="/mnt/p3"
export PATH="${PATH}:/opt/arpl"

/root/boot.sh
