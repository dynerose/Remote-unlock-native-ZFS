Remote-unlock-native-ZFS
Unlocking a native encrypted ZFS root partition remotely via Dropbear SSH server on Ubuntu

# 1: Prepare The Install Environment
# 1.1 Boot the Linux Live CD. If prompted, login with the username user and password live.
# Connect your system to the Internet as appropriate (e.g. join your WiFi network).

# 1.2 Optional: Install and start the OpenSSH server in the Live CD environment:
# If you have a second system, using SSH to access the target system can be convenient.
# adduser your_username
# addgroup your_username sudo

# 1.3 Become root:
sudo -i
apt-add-repository universe
apt --yes update
apt install --yes openssh-server
sudo systemctl restart ssh

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
# EF02 - BIOS Boot Partition, to store secondary boot loader (stage2 grub loader) (for non-UEFI)
# PARTITION_BIOS=2

# FD00 - ext4 boot partition
PARTITION_BOOT=3

# BF01 or 8300 Linux filesystem, to be encrypted and then used as primary ZFS pool
PARTITION_ZFS=4

# swap if you need
PARTITION_SWAP=5

# BF07 - Solaris Reserved 1
PARTITION_RSVD=9

# Finalize variable if you want run from script
read -p "Set a HOSTNAME : [info] " HOSTNAME && : ${HOSTNAME:=info} && echo "you answered: $HOSTNAME"
read -p "Type the name of the ubuntu distro: [eoan or focal] " DISTRO_NAME && : ${DISTRO_NAME:=focal} && echo "you answered: $DISTRO_NAME"
read -p "Set a name for the ZFS pool: [rpool] " RPOOL && : ${RPOOL:=rpool} && echo "you answered: $RPOOL" 
read -p "Set a name for the ZFS pool: [password] " ZFS_PASSPHRASE && :${ZFS_PASSPHRASE:=password} && echo "you answered: $ZFS_PASSPHRASE"
read -p "Set a username for the new system: [sa] " USERNAME && : ${USERNAME:=sa} && echo "you answered: $USERNAME"
read -p "Set a password for the new system/user: [password] " PASSWORD && : ${PASSWORD:=sa} && echo "you answered: $PASSWORD"
def=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}') 
read -e -p "Type the name of your network interface: " -i "$def" IFACE && : ${IFACE:=$defa} && echo "Network interface set to $IFACE"
read -e -p "$IFACE address mask (192.168.100.) to install: " -i 192.168.100. IFACEMASK && echo "address mask 1 set to $IFACEMASK"
read -e -p "$IFACE address (${IFACEMASK}10) to install: " -i ${IFACEMASK}10 IFACEADDRESS && echo "address mask 1 set to $IFACEADDRESS"
read -e -p "Gateway for $IFACE  (${IFACEMASK}2) : " -i ${IFACEMASK}2 GATEWAYADDRESS && echo "Gateway address set to $GATEWAYADDRESS"
read -p "Set time zone: [Europe/Budapest] " YOUR_TIME_ZONE && : ${YOUR_TIME_ZONE:=Europe/Budapest} && echo "you answered:
$YOUR_TIME_ZONE"
ls -la /dev/disk/by-id &&
echo "Enter Disk ID (must match exactly):"
# Select forst sda disk 
def=$(ls -l /dev/disk/by-id/ | grep '/sda$' | grep -o 'ata[^ ]*')
read -p "Enter Disk ID for ZFS disk a: [$def] " DISK && : ${DISK:=$def} && echo "you answered: /dev/disk/by-id/$DISK"

# if you have previous install
# umount /mnt/install/boot/efi
# umount /mnt/install/boot
# mount | grep -v zfs | tac | awk '/\/mnt/ {print $3}' | xargs -i{} umount -lf {}
# pid=lsof /mnt/install
# kill -9 ,all of them,
# zpool export -a
# zfs destroy -r available_rpool

# 1.4 Install ZFS in the Live CD environment:
apt-add-repository universe
apt install --yes debootstrap gdisk dkms dpkg-dev
apt install --yes zfs-dkms
apt install --yes zfsutils-linux

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
-O canmount=off -O mountpoint=none -R $INSTALL_DIR $RPOOL /dev/disk/by-id/$DISK-part$PARTITION_ZFS  -f

# Check > root@ubuntu:/#zpool list
# root@ubuntu:/#NAME    SIZE  ALLOC   FREE  CKPOINT  EXPANDSZ FRAG   CAP  DEDUP    HEALTH  ALTROOT
# root@ubuntu:/#rpool    18G   492K  18.0G        -         - 0%     0%   1.00x    ONLINE  /mnt/install/

# Step 3: System Installation
# 3.1 Create filesystem datasets for the root filesystems:

zfs create -o canmount=noauto -o mountpoint=/ $RPOOL/root
zfs mount $RPOOL/root
# Check > root@ubuntu:/# zfs list
# root@ubuntu:/#NAME         USED  AVAIL     REFER  MOUNTPOINT
# root@ubuntu:/#rpool        804K  17.4G      192K  none
# root@ubuntu:/#rpool/root   192K  17.4G      192K  /mnt/install/

# 3.2 Install GRUB for UEFI booting
yes | mkfs.ext4 /dev/disk/by-id/$DISK-part$PARTITION_BOOT
mkdir -p ${INSTALL_DIR}boot
mount /dev/disk/by-id/$DISK-part$PARTITION_BOOT ${INSTALL_DIR}boot/ -t ext4

apt install dosfstools
mkfs.msdos -F 32 -n EFI /dev/disk/by-id/$DISK-part${PARTITION_EFI}
mkdir -p ${INSTALL_DIR}boot/efi
mount /dev/disk/by-id/$DISK-part${PARTITION_EFI} ${INSTALL_DIR}boot/efi


# 3.3 Create other datasets:
# if you want others , for example
#zfs create                                 rpool/home
#zfs create -o mountpoint=/root             rpool/home/root
#zfs create -o canmount=off                 rpool/var
#zfs create -o canmount=off                 rpool/var/lib
#zfs create                                 rpool/var/log
#zfs create                                 rpool/var/spool
#zfs create -o com.sun:auto-snapshot=false  rpool/var/cache
#zfs create -o com.sun:auto-snapshot=false  rpool/var/tmp
#chmod 1777 /mnt/var/tmp
#zfs create                                 rpool/opt
#zfs create -o canmount=off                 rpool/usr
#zfs create                                 rpool/usr/local
#zfs create                                 rpool/var/mail
#zfs create -o com.sun:auto-snapshot=false  rpool/var/lib/docker
#zfs create -o com.sun:auto-snapshot=false  rpool/tmp
#chmod 1777 /mnt/tmp

# 3.4 Install the minimal system:
INCLUDES='--include tzdata,wget,nano'

# debootstrap eoan /mnt/
debootstrap $INCLUDES  $DISTRO_NAME $INSTALL_DIR
zfs set devices=off $RPOOL

# Step 4: System Configuration
# 4.1 Configure system
# Our newly copied system is lacking a few files and we should make sure
they exist before proceeding. the hostname (change HOSTNAME to the
desired hostname).
echo $HOST >  ${INSTALL_DIR}etc/hostname

cat > ${INSTALL_DIR}etc/apt/sources.list << EOLIST
deb http://archive.ubuntu.com/ubuntu ${DISTRO_NAME} main universe
restricted multiverse
deb-src http://archive.ubuntu.com/ubuntu ${DISTRO_NAME}  main universe
restricted multiverse
deb http://security.ubuntu.com/ubuntu ${DISTRO_NAME}-security main
universe restricted multiverse
deb-src http://security.ubuntu.com/ubuntu ${DISTRO_NAME}-security main
universe restricted multiverse
deb http://archive.ubuntu.com/ubuntu ${DISTRO_NAME}-updates main
universe restricted multiverse
deb-src http://archive.ubuntu.com/ubuntu ${DISTRO_NAME}-updates main
universe restricted multiverse
EOLIST

# 4.2 Configure the network interface:
cat > ${INSTALL_DIR}/etc/netplan/01-netcfg.yaml << EOF
network:
   renderer: networkd
   ethernets:
     ${IFACE}:
       addresses:
       - ${IFACEADDRESS}/24
       gateway4: ${GATEWAYADDRESS}
       nameservers:
         addresses:
         - 8.8.8.8
   version: 2
EOF
#If you are installing via WiFi, you might as well copy your wireless
credentials


#4.3 Bind the virtual filesystems from the LiveCD environment to the new
system and chroot into it:
mount --rbind /dev  ${INSTALL_DIR}dev
mount --rbind /proc ${INSTALL_DIR}proc
mount --rbind /sys  ${INSTALL_DIR}sys

#Finally we’re ready to “chroot” into our new system.
# check
# echo "DISK=$DISK PARTITION_EFI=$PARTITION_EFI
PARTITION_BOOT=$PARTITION_BOOT RPOOL=$RPOOL USER=$USER PASSWORD=$PASSWORD"
chroot ${INSTALL_DIR} /usr/bin/env DISK=$DISK
PARTITION_EFI=$PARTITION_EFI PARTITION_BOOT=$PARTITION_BOOT RPOOL=$RPOOL
USER=$USER PASSWORD=$PASSWORD bash --login
clear

#4.4 Configure a basic system environment:
apt update
#Let’s not forget to setup locale and time zone.
locale-gen --purge "en_US.UTF-8"
update-locale LANG=en_US.UTF-8 LANGUAGE=en_US
dpkg-reconfigure --frontend noninteractive locales
apt install --yes tzdata
echo "${YOUR_TIME_ZONE}" > /etc/timezone
dpkg-reconfigure --frontend noninteractive tzdata

# 4.6 Install latest Linux image and ZFS in the chroot environment for
the new system:
apt install --yes --no-install-recommends linux-image-generic
linux-headers-generic
apt install --yes dpkg-dev
echo "zfs-dkms zfs-dkms/note-incompatible-licenses note true" |
debconf-set-selections
apt install --yes zfs-dkms
apt install --yes zfs-initramfs grub-efi-amd64-signed shim-signed
# apt install --yes spl spl-dkms zfs-test zfsutils-linux
zfsutils-linux-dev zfs-zed

#4.7 Install GRUB for UEFI booting
# To mount EFI and boot partitions, we need to do some fstab setup too:
echo "UUID=$(blkid -s UUID -o value
/dev/disk/by-id/${DISK}-part${PARTITION_BOOT}) /boot ext4
noatime,nofail,x-systemd.device-timeout=1 0 1" >> /etc/fstab
echo "UUID=$(blkid -s UUID -o value
/dev/disk/by-id/$DISK-part$PARTITION_EFI) /boot/efi vfat
noatime,nofail,x-systemd.device-timeout=1 0 1" >> /etc/fstab

# Check the fstab
# cat /etc/fstab
# # UNCONFIGURED FSTAB FOR BASE SYSTEM
# UUID=c9f1ea66-5003-4cf2-88d4-cf5ea59780a7 /boot ext4
noatime,nofail,x-systemd.device-timeout=1 0 1
# UUID=9ba2437c-facb-49b5-acb8-9f0c12b760c2 /boot/efi vfat
noatime,nofail,x-systemd.device-timeout=1 0 1

sudo systemctl list-unit-files | grep zfs
# zfs-import-cache.service               enabled
# zfs-import-scan.service                disabled
# zfs-import.service                     masked
# zfs-load-module.service                enabled
# zfs-mount.service                      enabled
# zfs-share.service                      enabled
# zfs-volume-wait.service                enabled
# zfs-zed.service                        enabled
# zfs-import.target                      enabled
# zfs-volumes.target                     enabled
# zfs.target                             enabled
# All disabled service must be enabled

sudo systemctl enable zfs-import-cache.service
sudo systemctl enable zfs-import-scan.service
sudo systemctl enable zfs-import.service
sudo systemctl enable zfs-mount.service
sudo systemctl enable zfs-share.service
sudo systemctl enable zfs-volume-wait.service
sudo systemctl enable zfs-zed.service
sudo systemctl enable zfs-import.target
sudo systemctl enable zfs-volumes.target
sudo systemctl enable zfs.target

# Step 5: GRUB Installation
# 5.1 Verify that the ZFS boot filesystem is recognized:
grub-probe /boot
# ext2
#5.2 Refresh the initrd files:
KERNEL=`ls /usr/lib/modules/ | cut -d/ -f1 | sed 's/linux-image-//'`
update-initramfs -c -k $KERNEL
# update-initramfs -u -k all
# 5.3 Update the boot configuration:
sed -E 's>^(GRUB_CMDLINE_LINUX=")>\1root=ZFS=rpool/root>'
/etc/default/grub -i
# GRUB_DEFAULT=5
# GRUB_HIDDEN_TIMEOUT=0
# GRUB_HIDDEN_TIMEOUT_QUIET=true
# GRUB_TIMEOUT=5
# check gruf file
# cat /etc/default/grub
# ...
# GRUB_CMDLINE_LINUX="root=ZFS=rpool/root"
# ...
#sed -E
's>^(GRUB_CMDLINE_LINUX=")>\1ip=192.168.100.10::192.168.100.2:255.255.255.0::ens33:none
root=ZFS=rpool/root>' /etc/default/grub -i
#sed -E 's>^(GRUB_CMDLINE_LINUX=")>\1root=ZFS='$RPOOL'/root>'
/etc/default/grub -i

# This entry is used to prevent GRUB from adding the results of
os-prober to the menu.
# A value of "true" disables the os-prober check of other partitions for
operating systems,
# including Windows, Linux, OSX and Hurd, during execution of the
update-grub command.
# Necessary for zfa
echo 'GRUB_DISABLE_OS_PROBER=true' >> /etc/default/grub

#update-initramfs -u -k $KERNEL
update-initramfs -u -k all && update-grub

# 5.4 Install the boot loader
# I read somewhere in the internet the fstab won’t work properly
# when your ZFS starting first.
# set manual mount in crontab as a workaround until ZFS gets systemd loader.
( crontab -l ; echo "@reboot mount /boot ; mount /boot/efi" ) | crontab -

# 5.5 For UEFI booting, install GRUB:
grub-install --target=x86_64-efi --efi-directory=/boot/efi
--bootloader-id=ubuntu --recheck --no-floppy
# Verify that the ZFS module is installed:
# check
# root@ubuntu:/# ls /boot/grub/*/zfs.mod
# /boot/grub/x86_64-efi/zfs.mod


adduser --quiet --disabled-password --shell /bin/bash --home /home/$USER
--gecos "User" $USER
echo "$USER:$PASSWORD" | chpasswd
addgroup $USER sudo

# Other ,maybe neccessary, good application
apt install --yes openssh-server ssh nano lshw rsync mc ncdu ethtool
wget git gpart gparted ssh-askpass  net-tools tree htop ssh strace
apt install --yes p7zip p7zip-full p7zip-rar

# End of zfs install
# If you want a snapshot run this:
# zfs snapshot $RPOOL/root@install
# zfs list -t snapshot

#As install is ready, we can exit our chroot environment.
exit

# And cleanup our mount points.
umount /mnt/install/boot/efi
umount /mnt/install/boot
mount | grep -v zfs | tac | awk '/\/mnt/ {print $3}' | xargs -i{} umount
-lf {}
zpool export -a

#After the reboot you should be able to enjoy your installation.
reboot

# Your first start noy visible the zfs ask password dialog . Type it
blind and Enter. I do not know why.
# log in
sudo -i
netplan generate && netplan apply

# You can create a swap dataset.
# Your zfs datapool name RPOOL=rpool
RPOOL=rpool
zfs create -V 1G -b $(getconf PAGESIZE) -o compression=off -o
logbias=throughput -o sync=always -o primarycache=metadata -o
secondarycache=none $RPOOL/swap
mkswap -f /dev/zvol/$RPOOL/swap
echo "/dev/zvol/$RPOOL/swap none swap defaults 0 0" >> /etc/fstab
echo RESUME=none > /etc/initramfs-tools/conf.d/resume

apt dist-upgrade --yes
apt update &&
# logrotate if you want
for file in /etc/logrotate.d/* ; do
     if grep -Eq "(^|[^#y])compress" "$file" ; then
         sed -i -r "s/(^|[^#y])(compress)/\1#\2/" "$file"
     fi
done


# Unlocking a native encrypted ZFS root partition remotely via Dropbear
SSH server
# exit if zou are in root
# exit
ls -l ~/.ssh/id_*.pub
# If there are existing keys, you can either use those and skip the next
step or backup up the old keys and generate new ones.
# Generate a new 4096 bits SSH key pair with your email address as a
comment by typing:
mkdir ~/.ssh
chmod 700 ~/.ssh
ssh-keygen -t rsa -b 4096 -C "your_email@domain.com"
# To verify your new SSH key pair is generated, type:
ls ~/.ssh/id_*
# Copy the Public Key to Ubuntu Server
# Now that you generated your SSH key pair, the next step is to copy the
public key to the server you want to manage.
# The easiest and the recommended way to copy your public key to the
server is to use a utility called ssh-copy-id. On your local machine
terminal type:
# ssh-copy-id remote_username@server_ip_address
# If by some reason the ssh-copy-id utility is not available on your
local computer, you can use the following command to copy the public key:
# cat ~/.ssh/id_rsa.pub | ssh remote_username@server_ip_address "mkdir
-p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod
600 ~/.ssh/authorized_keys"
# Disabling the password authentication adds an extra layer of security
to your server.

sed -i "s/.*RSAAuthentication.*/RSAAuthentication yes/g"
/etc/ssh/sshd_config
sed -i "s/.*PubkeyAuthentication.*/PubkeyAuthentication yes/g"
/etc/ssh/sshd_config
sed -i "s/.*PasswordAuthentication.*/PasswordAuthentication no/g"
/etc/ssh/sshd_config
sed -i
"s/.*AuthorizedKeysFile.*/AuthorizedKeysFile\t\.ssh\/authorized_keys/g"
/etc/ssh/sshd_config
sed -i "s/.*PermitRootLogin.*/PermitRootLogin no/g" /etc/ssh/sshd_config
echo "sa      ALL=(ALL)       NOPASSWD: ALL" >> /etc/sudoers
sudo systemctl restart ssh

# Install on server
sudo apt install --yes dropbear busybox

# Enable and configure
sudo -i


sed -i 's/NO_START=1/NO_START=0/g'  /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=2222/g' /etc/default/dropbear
sed -i '/BUSYBOX=auto/c\BUSYBOX=y' /etc/initramfs-tools/initramfs.conf
sudo echo "DROPBEAR=y" >> /etc/initramfs-tools/initramfs.conf
m_value='DROPBEAR_OPTIONS="-p 2222 -s -j -k -I 60"'
sudo sed -i "s/.*DROPBEAR_OPTIONS.*/${m_value}/g"
/etc/dropbear-initramfs/config

def=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}') &&
read -e -p "Type the name of your network interface: " -i "$def" IFACE
&& : ${IFACE:=$defa} && echo "Network interface set to $IFACE" &&
read -e -p "$IFACE address mask (192.168.100.) to install: " -i
192.168.100. IFACEMASK && echo "address mask 1 set to $IFACEMASK" &&
read -e -p "$IFACE address (${IFACEMASK}10) to install: " -i
${IFACEMASK}10 IFACEADDRESS && echo "address mask 1 set to $IFACEADDRESS" &&
read -e -p "Gateway for $IFACE  (${IFACEMASK}2) : " -i ${IFACEMASK}2
GATEWAYADDRESS && echo "Gateway address set to $GATEWAYADDRESS"

# Create a static IP (or skip this step to use DHCP (but I never use
DHCP , not tested that)
# Edit /etc/initramfs-tools/initramfs.conf to add (or change) the line:
cp /etc/initramfs-tools/initramfs.conf
/etc/initramfs-tools/initramfs.conf.old
cat > /etc/initramfs-tools/initramfs.conf << EOF
MODULES=most
BUSYBOX=y
DROPBEAR=y
COMPCACHE_SIZE=""
COMPRESS=lz4
DEVICE=${IFACE}
IP=${IFACEADDRESS}::${GATEWAYADDRESS}:255.255.255.0::${IFACE}:off
NFSROOT=auto
RUNSIZE=10%
EOF

# The initramfs static IP configuration will cause the Ubuntu server to
freeze for some time during the boot process.
# To overcome this problem, down the network adapter after the initramfs.
# Edit the /usr/share/initramfs-tools/scripts/init-bottom/dropbear
echo "ifconfig ${IFACE} 0.0.0.0 down" >>
/usr/share/initramfs-tools/scripts/init-bottom/dropbear

# Generate our keys, convert the openssh key to dropbear format, and
copy all of the files into /etc/dropbear-initramfs where they belong.
# not ins sudo
cd ~/.ssh
dropbearkey -t dss -f dropbear_dss_host_key
dropbearkey -t rsa -f dropbear_rsa_host_key
dropbearkey -t rsa -f id_rsa.dropbear
/usr/lib/dropbear/dropbearconvert dropbear openssh id_rsa.dropbear id_rsa
touch id_rsa.pub
dropbearkey -y -f id_rsa.dropbear |grep "^ssh-rsa " > id_rsa.pub
touch authorized_keys
cat id_rsa.pub >> authorized_keys
sudo cp dropbear_* /etc/dropbear-initramfs/
sudo cp id_* /etc/dropbear-initramfs/
sudo cp authorized_keys /etc/dropbear-initramfs/

#Note, if you don’t HAVE a /etc/dropbear-initramfs folder, do the following:
sudo mkdir /etc/initramfs-tools/root
sudo mkdir /etc/initramfs-tools/root/.ssh
sudo cp dropbear_* /etc/initramfs-tools/root/.ssh/
sudo cp id_* /etc/initramfs-tools/root/.ssh/
sudo cp authorized_keys /etc/initramfs-tools/root/.ssh/

# Create the crypt_unlock script
# /etc/initramfs-tools/hooks/crypt_unlock.sh

sudo -i
cat > /usr/share/initramfs-tools/hooks/crypt_unlock.sh << EOFD
#!/bin/sh
PREREQ="dropbear"

prereqs() {
echo "$PREREQ"
}

case "$1" in
prereqs)
prereqs
exit 0
;;
esac

. "${CONFDIR}/initramfs.conf"
. /usr/share/initramfs-tools/hook-functions

if [ "${DROPBEAR}" != "n" ] && [ -r "/etc/zfs" ] ; then
cat > "${DESTDIR}/bin/unlock" << EOF
#!/bin/sh
if PATH=/lib/unlock:/bin:/sbin /scripts/local-top/cryptroot; then
/sbin/zfs load-key -a
# rpool/root your zpool name and root zfs name and the mountpoint
mount -o zfsutil -t zfs rpool/root /

kill \`ps | grep zfs | grep -v "grep" | awk '{print \$1}'\`
kill \`ps | grep plymouth | grep -v "grep" | awk '{print \$1}'\`
kill \`ps | grep cryptroot | grep -v "grep" | awk '{print \$1}'\`
# following line kill the remote shell right after the passphrase has
been entered.
kill -9 \`ps | grep "\-sh" | grep -v "grep" | awk '{print \$1}'\`

exit 0
fi
exit 1
EOF

chmod 755 "${DESTDIR}/bin/unlock"

mkdir -p "${DESTDIR}/lib/unlock"
cat > "${DESTDIR}/lib/unlock/plymouth" << EOF
#!/bin/sh
[ "\$1" == "--ping" ] && exit 1
/bin/plymouth "\$@"
EOF

chmod 755 "${DESTDIR}/lib/unlock/plymouth"

echo To unlock root-partition run "unlock" >> ${DESTDIR}/etc/motd

fi


chmod 755 "${DESTDIR}/lib/unlock/plymouth"
echo To unlock root-partition run "unlock" >> ${DESTDIR}/etc/motd
fi
EOFD

chmod +x /usr/share/initramfs-tools/hooks/crypt_unlock.sh

update-initramfs -u -k all
update-grub


# Copy the ssh keys. Note: Password logins for root is disabled by
default dropbear configuration.
# sudo cp /etc/initramfs-tools/root/.ssh/id_rsa ~/.ssh/id_rsa_dropbear
sudo cp /etc/dropbear-initramfs/id_rsa ~/.ssh/id_rsa_dropbear
sudo chown $USER:$USER ~/.ssh/id_rsa_dropbear

# Copy the id_rsa_dropbear
# For real world setup, you should already generated your personal key.
# With that, just append your public key to the dropbear’s
/etc/initramfs-tools/root/.ssh/authorized_keys

sudo -i
cat /home/$USER/.ssh/id_rsa.pub >> /etc/dropbear-initramfs/authorized_keys

# Disable dropbear on your booted system.
#sudo update-rc.d dropbear disable
systemctl disable dropbear

# KERNEL=`ls /usr/lib/modules/ | cut -d/ -f1 | sed 's/linux-image-//'`
# update-initramfs -u -k $KERNEL
update-initramfs -u -k all && update-grub

# How to Convert OpenSSH keys to Putty (.ppk) on Linux
# sudo apt install -y  putty-tools
# puttygen keyname -o keyname.ppk

# for example
# cd /home/username/.ssh
# puttygen id_rsa_dropbear -o drop.ppk

# COPY DROPBEAR SSH KEY
scp server:/home/username/id_rsa ~/.ssh/id_rsa_dropbear_server # on client


# CONNECT TO SERVER
