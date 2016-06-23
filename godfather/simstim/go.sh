#!/bin/bash
PATH_TO_VMX="/home/joystick/vmware/Windows_7/Windows 7.vmx"
SNAPSHOT="SEL"


COUNT=0
while true;
do
    echo " [*] Starting round $COUNT"
    echo " [***] Restoring snapshot ..."
    vmrun -T ws revertToSnapshot "$PATH_TO_VMX" $SNAPSHOT # >/dev/null
    echo " [***] Done"
    echo " [***] Restarting machine ..."
    vmrun -T ws start "$PATH_TO_VMX" nogui #>/dev/null
    echo " [***] Done"
    echo " [***] Sleeping..."
    sleep 1800
    echo " [***] Done"
    echo " [***] Storing serial log"
    mv /dev/shm/serial3.txt logs/$(date +"%d%m-%H%M%S.txt")
    echo " [***] Done"
    echo " [*] Round $COUNT done"
    echo
    COUNT=$(expr $COUNT + 1)
done
