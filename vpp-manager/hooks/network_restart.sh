#!/bin/sh

chroot /host /bin/sh <<"EOSCRIPT"

if which systemctl > /dev/null; then
    echo "Using systemctl"
    if systemctl status systemd-networkd > /dev/null 2>&1; then
        echo "Using systemd-networkd"
        systemctl restart systemd-networkd
    elif systemctl status NetworkManager > /dev/null 2>&1; then
        echo "Using NetworkManager"
        systemctl restart NetworkManager
    elif systemctl status networking > /dev/null 2>&1; then
        echo "Using networking service"
        systemctl restart networking
    elif systemctl status network > /dev/null 2>&1; then
        echo "Using network service"
        systemctl restart network
    else
        echo "Networking backend not detected, network configuration may fail"
        exit 1
    fi
else
    echo "Init system not supported, network configuration may fail"
    exit 1
fi

EOSCRIPT
