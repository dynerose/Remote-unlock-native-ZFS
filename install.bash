# 1: Prepare The Install Environment
# 1.1 Boot the Linux Live CD. If prompted, login with the username user and password live.
# Connect your system to the Internet as appropriate (e.g. join your WiFi network).

# 1.2 Optional: Install and start the OpenSSH server in the Live CD environment:
# If you have a second system, using SSH to access the target system can be convenient.
# adduser your_username
# addgroup your_username sudo

# 1.3 Become root:
sudo -i apt-add-repository universe apt --yes update apt install --yes openssh-server sudo systemctl restart ssh
# in Openssh client
# log in your_username
# Necessary variable
# Set variable

HOST=host_server
RPOOL=your_rpool_name
ZFS_PASSPHRASE=your_zfs_p
USER=your_username
PASSWORD=password
IFACE=ens33
IFACEMASK=192.168.100.
GATEWAYADDRESS=192.168.100.2
YOUR_TIME_ZONE=Europe/Budapest
INSTALL_DIR=/mnt/install/ 
DISK=
# for example
# DISK=ata-WDC_WDS240G2G0B-00EPW0_192230806682
# Ubuntu 19.10
# DISTRO_NAME=eoan
# UBuntu 20.04
DISTRO_NAME=focal

# EF00 - EFI System Partition (ESP), to make system bootable in UEFI (see "UEFI booting" below)
PARTITION_EFI=1

# Not tested
EF02 - BIOS Boot Partition, to store secondary boot loader (stage2 grub loader) (for non-UEFI)
# PARTITION_BIOS=2

# FD00 - ext4 boot partition
PARTITION_BOOT=3
# BF01 or 8300 Linux filesystem, to be encrypted and then used as primary ZFS pool

PARTITION_ZFS=4
# swap if you need
PARTITION_SWAP=5

# BF07 - Solaris Reserved 1
PARTITION_RSVD=9

def=$(ls -l /dev/disk/by-id/ | grep '/sda$' | grep -o 'ata[^ ]*')
read -p "Enter Disk ID for ZFS disk a: [$def] " DISK && : ${DISK:=$def} && echo "you answered: /dev/disk/by-id/$DISK"

# if you have previous install
# umount /mnt/install/boot/efi
# umount /mnt/install/boot
# mount | grep -v zfs | tac | awk '//mnt/ {print $3}' | xargs -i{} umount -lf {}
# pid=lsof /mnt/install
# kill -9 ,all of them,
# zpool export -a
# zfs destroy -r available_rpool

1.4 Install ZFS in the Live CD environment:

apt-add-repository universe apt install --yes debootstrap gdisk dkms dpkg-dev
apt install --yes zfs-dkms apt install --yes zfsutils-linux

# Step 2: Disk Formatting
# 2.1 Partition your disk(s):
sgdisk --zap-all /dev/disk/by-id/$DISK
# for UEFI booting
sgdisk -n1:1M:+512M -t1:EF00 -c1:EFI /dev/disk/by-id/$DISK
# create boot partition
sgdisk -n2:0:+1G -t2:8300 -c2:Boot /dev/disk/by-id/$DISK
# create root partition native ZFS encryption
sgdisk -n3:0:0 -t3:BF01 -c3:Ubuntu /dev/disk/by-id/$DISK
# inform kernel on partition table change
partprobe
# print partition table
sgdisk --print /dev/disk/by-id/$DISK

# Check a your disk partitions have a line in /dev/disk/by-uuid/ !!! 

# setup encryption on root partition
# 2.2 Create rot pool ZFS native encryption :

echo -n "$ZFS_PASSPHRASE" | zpool create -o ashift=12 -O compression=lz4 -O normalization=formD \
-O acltype=posixacl -O xattr=sa -O dnodesize=auto -O atime=off \
-O encryption=aes-256-gcm -O keylocation=prompt -O keyformat=passphrase \
-O canmount=off -O mountpoint=none -R $INSTALL_DIR $RPOOL /dev/disk/by-id/$DISK-part$PARTITION_ZFS -f

# Check > root@ubuntu:/#zpool list
# root@ubuntu:/#NAME SIZE ALLOC FREE CKPOINT EXPANDSZ FRAG CAP DEDUP HEALTH ALTROOT
# root@ubuntu:/#rpool 18G 492K 18.0G - - 0% 0% 1.00x ONLINE /mnt/install/

# Step 3: System Installation
# 3.1 Create filesystem datasets for the root filesystems:

zfs create -o canmount=noauto -o mountpoint=/ $RPOOL/root zfs mount $RPOOL/root
# Check > root@ubuntu:/# zfs list
# root@ubuntu:/#NAME USED AVAIL REFER MOUNTPOINT
# root@ubuntu:/#rpool 804K 17.4G 192K none
# root@ubuntu:/#rpool/root 192K 17.4G 192K /mnt/install/

# 3.2 Install GRUB for UEFI booting
yes | mkfs.ext4 /dev/disk/by-id/$DISK-part$PARTITION_BOOT
mkdir -p ${INSTALL_DIR}boot
mount /dev/disk/by-id/$DISK-part$PARTITION_BOOT ${INSTALL_DIR}boot/ -t ext4

apt install --yes dosfstools
mkfs.msdos -F 32 -n EFI /dev/disk/by-id/$DISK-part${PARTITION_EFI}
mkdir -p ${INSTALL_DIR}boot/efi mount /dev/disk/by-id/$DISK-part${PARTITION_EFI} ${INSTALL_DIR}boot/efi

# 3.3 Create other datasets:
# if you want others , for example

#zfs create rpool/home #zfs create -o mountpoint=/root rpool/home/root
#zfs create -o canmount=off rpool/var
#zfs create -o canmount=off rpool/var/lib
#zfs create rpool/var/log 
#zfs create rpool/var/spool 
#zfs create -o com.sun:auto-snapshot=false rpool/var/cache
#zfs create -o com.sun:auto-snapshot=false rpool/var/tmp 
#chmod 1777 /mnt/var/tmp 
#zfs create rpool/opt 
#zfs create -o canmount=off rpool/usr 
#zfs create rpool/usr/local #zfs create rpool/var/mail 
#zfs create -o com.sun:auto-snapshot=false rpool/var/lib/docker 
#zfs create -o com.sun:auto-snapshot=false rpool/tmp 
#chmod 1777 /mnt/tmp

# 3.4 Install the minimal system:

INCLUDES='--include tzdata,wget,nano'
debootstrap $INCLUDES $DISTRO_NAME $INSTALL_DIR zfs set devices=off $RPOOL

# Step 4: System Configuration
# 4.1 Configure system
# Our newly copied system is lacking a few files and we should make sure they exist before proceeding. 
# the hostname (change HOSTNAME to the desired hostname). 
echo $HOST > ${INSTALL_DIR}etc/hostname

cat > ${INSTALL_DIR}etc/apt/sources.list << EOLIST
deb http://archive.ubuntu.com/ubuntu ${DISTRO_NAME} main universe restricted multiverse
deb-src http://archive.ubuntu.com/ubuntu ${DISTRO_NAME} main universe restricted multiverse 
deb http://security.ubuntu.com/ubuntu ${DISTRO_NAME}-security main universe restricted multiverse
deb-src http://security.ubuntu.com/ubuntu ${DISTRO_NAME}-security main universe restricted multiverse
deb http://archive.ubuntu.com/ubuntu ${DISTRO_NAME}-updates main universe restricted multiverse 
deb-src http://archive.ubuntu.com/ubuntu ${DISTRO_NAME}-updates main universe restricted multiverse 
EOLIST

# 4.2 Configure the network interface:
cat > ${INSTALL_DIR}/etc/netplan/01-netcfg.yaml << EOF 
network: 
  renderer: 
    networkd 
  ethernets: ${IFACE}: 
    addresses: - ${IFACEADDRESS}/24 
    gateway4: ${GATEWAYADDRESS}
    nameservers: 
      addresses: - 8.8.8.8 
  version: 2
EOF 
# If you are installing via WiFi, you might as well copy your wireless credentials

# 4.3 Bind the virtual filesystems from the LiveCD environment to the new system and chroot into it: 
mount --rbind /dev ${INSTALL_DIR} dev
mount --rbind /proc ${INSTALL_DIR}proc 
mount --rbind /sys ${INSTALL_DIR}sys

# Finally we’re ready to “chroot” into our new system.
# check
# echo "DISK=$DISK PARTITION_EFI=$PARTITION_EFI PARTITION_BOOT=$PARTITION_BOOT RPOOL=$RPOOL USER=$USER PASSWORD=$PASSWORD" 

chroot ${INSTALL_DIR} /usr/bin/env \
DISK=$DISK PARTITION_EFI=$PARTITION_EFI PARTITION_BOOT=$PARTITION_BOOT RPOOL=$RPOOL USER=$USER PASSWORD=$PASSWORD \
bash --login clear

# 4.4 Configure a basic system environment: 
apt update --yes
# Let’s not forget to setup locale and time zone.
locale-gen --purge "en_US.UTF-8"
update-locale LANG=en_US.UTF-8 LANGUAGE=en_US 
dpkg-reconfigure --frontend noninteractive locales 
apt install --yes tzdata 
echo "${YOUR_TIME_ZONE}" > /etc/timezone 
dpkg-reconfigure --frontend noninteractive tzdata

# 4.6 Install latest Linux image and ZFS in the chroot environment for
# the new system: 
apt install --yes --no-install-recommends linux-image-generic linux-headers-generic 
apt install --yes dpkg-dev 
echo "zfs-dkms zfs-dkms/note-incompatible-licenses note true" | debconf-set-selections 
apt install --yes zfs-dkms 
apt install --yes zfs-initramfs grub-efi-amd64-signed shim-signed
apt install --yes zfsutils-linux 

# 4.7 Install GRUB for UEFI booting
# To mount EFI and boot partitions, we need to do some fstab setup too:
echo "UUID=$(blkid -s UUID -o value /dev/disk/by-id/${DISK}-part${PARTITION_BOOT}) /boot \
ext4 noatime,nofail,x-systemd.device-timeout=1 0 1" >> /etc/fstab
echo "UUID=$(blkid -s UUID -o value /dev/disk/by-id/$DISK-part$PARTITION_EFI) /boot/efi \
vfat noatime,nofail,x-systemd.device-timeout=1 0 1" >> /etc/fstab
# Check the fstab
cat /etc/fstab
# UNCONFIGURED FSTAB FOR BASE SYSTEM
# UUID=c9f1ea66-5003-4cf2-88d4-cf5ea59780a7 /boot ext4 noatime,nofail,x-systemd.device-timeout=1 0 1
# UUID=9ba2437c-facb-49b5-acb8-9f0c12b760c2 /boot/efi vfat noatime,nofail,x-systemd.device-timeout=1 0 1

sudo systemctl list-unit-files | grep zfs
# zfs-import-cache.service enabled
# zfs-import-scan.service disabled
# zfs-import.service masked
# ...

# All disabled service must be enabled
sudo systemctl enable zfs-import-scan.service 

# Step 5: GRUB Installation
# 5.1 Verify that the ZFS boot filesystem is recognized:
grub-probe /boot
# ext2

# 5.2 Refresh the initrd files: 

# 5.3 Update the boot configuration:
sed -E 's>^(GRUB_CMDLINE_LINUX=")>\1root=ZFS=rpool/root>' /etc/default/grub -i
# check gruf file
cat /etc/default/grub
# ...
# GRUB_CMDLINE_LINUX="root=ZFS=rpool/root"
# ...

# This entry is used to prevent GRUB from adding the results of os-prober to the menu.
# A value of "true" disables the os-prober check of other partitions for operating systems,
# including Windows, Linux, OSX and Hurd, during execution of the
# Necessary for zfa
echo 'GRUB_DISABLE_OS_PROBER=true' >> /etc/default/grub 

KERNEL=`ls /usr/lib/modules/ | cut -d/ -f1 | sed 's/linux-image-//'`
update-initramfs -c -k $KERNEL
# update-initramfs -u -k all
update-grub

# 5.4 Install the boot loader
# I read somewhere in the internet the fstab won’t work properly when your ZFS starting first.
# set manual mount in crontab as a workaround until ZFS gets systemd loader.
( crontab -l ; echo "@reboot mount /boot ; mount /boot/efi" ) | crontab -

# 5.5 For UEFI booting, install GRUB:
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ubuntu --recheck --no-floppy
# Verify that the ZFS module is installed:
ls /boot/grub/*/zfs.mod
# /boot/grub/x86_64-efi/zfs.mod

# Adduser for new system
adduser --quiet --disabled-password --shell /bin/bash --home /home/$USER --gecos "User" $USER 
echo "$USER:$PASSWORD" | chpasswd 
addgroup $USER sudo

# Other ,maybe neccessary, good application
apt install --yes openssh-server ssh nano lshw rsync mc ncdu ethtool wget git gpart gparted 
apt install --yes ssh-askpass net-tools tree htop ssh strace 
apt install --yes p7zip p7zip-full p7zip-rar

# End of zfs install
# If you want a snapshot run this:
# zfs snapshot $RPOOL/root@install
# zfs list -t snapshot

# As install is ready, we can exit our chroot environment. 
exit
# And cleanup our mount points.
umount $INSTALL_DIR/boot/efi 
umount $INSTALL_DIR/boot 
mount | grep -v zfs | tac | awk '//mnt/ {print $3}' | xargs -i{} umount -lf {} 
zpool export -a

# After the reboot you should be able to enjoy your installation. 
reboot

# Your first start noy visible the zfs ask password dialog . Type it blind and Enter. I do not know why.
# log in

sudo -i 
netplan generate && netplan apply
# You can create a swap dataset.
# Your zfs datapool name RPOOL=rpool
RPOOL=rpool 
zfs create -V 1G -b $(getconf PAGESIZE) \
-o compression=off \
-o logbias=throughput \
-o sync=always \
-o primarycache=metadata \
-o secondarycache=none \
$RPOOL/swap mkswap -f /dev/zvol/$RPOOL/swap 

echo "/dev/zvol/$RPOOL/swap none swap defaults 0 0" >> /etc/fstab 
echo RESUME=none > /etc/initramfs-tools/conf.d/resume

apt dist-upgrade --yes apt update &&
# logrotate if you want

for file in /etc/logrotate.d/* ; do 
if grep -Eq "(^|[^#y])compress" "$file" ; then 
sed -i -r "s/(^|[^#y])(compress)/\1#\2/" "$file" 
fi 
done
