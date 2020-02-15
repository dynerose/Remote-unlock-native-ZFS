Remote-unlock-native-ZFS
Unlocking a native encrypted ZFS root partition remotely via Dropbear SSH server on Ubuntu

Utility for unattended remote unlock of native ZFS encrypted root disk partition using SSH. 
Requires dropbear SSH server which could be run from initial ramdisk.

Server will be unlocked when SSH is available on the specified IP address and port and if the fingerprint in the known_hosts file matches. 

You should always use IP addresses in the host configuration.

Please also note that the server boot partition type ext (because zfs boot partition not tested yet)
The remote unlock script that I created 
   /usr/share/initramfs-tools/hooks/crypt_unlock.sh
not a nice solution but working.

I accept any ideas and help to make the solution nicer and thank you for it.

License

This software is licensed under MIT license.
