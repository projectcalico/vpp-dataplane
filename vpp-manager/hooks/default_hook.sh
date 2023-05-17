#!/bin/sh

HOOK="$0"
chroot /host /bin/sh <<EOSCRIPT

fix_dns () {
    if systemctl status NetworkManager > /dev/null 2>&1; then
        echo "default_hook: system is using NetworkManager; fixing dns..."
        sed -i "s/\[main\]/\[main\]\ndns=none/" /etc/NetworkManager/NetworkManager.conf
        systemctl daemon-reload
        systemctl restart NetworkManager
    fi
}

undo_dns_fix () {
    if systemctl status NetworkManager > /dev/null 2>&1; then
        echo "default_hook: system is using NetworkManager; undoing dns fix..."
        sed -i "0,/dns=none/{/dns=none/d;}" /etc/NetworkManager/NetworkManager.conf
        systemctl daemon-reload
        systemctl restart NetworkManager
    fi
}

restart_network () {
    if systemctl status systemd-networkd > /dev/null 2>&1; then
        echo "default_hook: system is using systemd-networkd; restarting..."
        systemctl restart systemd-networkd
    elif systemctl status NetworkManager > /dev/null 2>&1; then
        echo "default_hook: system is using NetworkManager; restarting..."
        systemctl restart NetworkManager
    elif systemctl status networking > /dev/null 2>&1; then
        echo "default_hook: system is using networking service; restarting..."
        systemctl restart networking
    elif systemctl status network > /dev/null 2>&1; then
        echo "default_hook: system is using network service; restarting..."
        systemctl restart network
    else
        echo "default_hook: Networking backend not detected, network configuration may fail"
    fi
}

if which systemctl > /dev/null; then
    echo "default_hook: using systemctl..."
else
    echo "default_hook: Init system not supported, network configuration may fail"
    exit 1
fi

if [ "$HOOK" = "BEFORE_VPP_RUN" ]; then
    fix_dns
elif [ "$HOOK" = "VPP_RUNNING" ]; then
    restart_network
elif [ "$HOOK" = "VPP_DONE_OK" ]; then
    undo_dns_fix
    restart_network
elif [ "$HOOK" = "VPP_ERRORED" ]; then
    undo_dns_fix
    restart_network
fi

EOSCRIPT
