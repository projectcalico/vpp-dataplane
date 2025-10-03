#!/bin/sh

HOOK="$0"
INTERFACE_NAME="$1"
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

save_network_file () {
  if dmidecode -s bios-vendor | grep "Amazon EC2"; then
    if systemctl status systemd-networkd > /dev/null 2>&1; then
      if ip addr show "$INTERFACE_NAME" | grep -w inet | grep dynamic; then
        if networkctl list | grep "$INTERFACE_NAME" | grep "configured"; then
          networkctl status $INTERFACE_NAME | grep "Network File:" | sed "s/Network File: //" | xargs cat > /tmp/$INTERFACE_NAME.network.orig
          cat /tmp/$INTERFACE_NAME.network.orig
        fi
      fi
    fi
  fi
}

tweak_network_file () {
  if dmidecode -s bios-vendor | grep "Amazon EC2"; then
    if systemctl status systemd-networkd > /dev/null 2>&1; then
      if ip addr show "$INTERFACE_NAME" | grep -w inet | grep dynamic; then
        if networkctl list | grep "$INTERFACE_NAME" | grep "unmanaged"; then
          echo "default_hook: uplink interface, $INTERFACE_NAME, in unmanaged state; Fixing..."
          echo "[Match]" > /tmp/$INTERFACE_NAME.network
          echo "Name=$INTERFACE_NAME" >> /tmp/$INTERFACE_NAME.network
          echo >> /tmp/$INTERFACE_NAME.network
          sed "/^\[Match\]/,/^$/d" /tmp/$INTERFACE_NAME.network.orig >> /tmp/$INTERFACE_NAME.network
          cp /tmp/$INTERFACE_NAME.network /etc/systemd/network/$INTERFACE_NAME.network
          chmod 644 /etc/systemd/network/$INTERFACE_NAME.network
          touch /var/run/vpp/network_file_tweaked
          rm /tmp/$INTERFACE_NAME.network*
          systemctl daemon-reload
          systemctl restart systemd-networkd
        fi
      fi
    fi
  fi
}

remove_tweaked_network_file () {
  if [ -f /var/run/vpp/network_file_tweaked ]; then
    rm /etc/systemd/network/$INTERFACE_NAME.network
    rm /var/run/vpp/network_file_tweaked
    echo "default_hook: Deleting tweaked network file..."
  fi
}

echo "default_hook: Uplink interface name=$INTERFACE_NAME"
if which systemctl > /dev/null; then
    echo "default_hook: using systemctl..."
else
    echo "default_hook: Init system not supported, network configuration may fail"
    exit 1
fi

if [ "$HOOK" = "BEFORE_VPP_RUN" ]; then
    fix_dns
    save_network_file
elif [ "$HOOK" = "VPP_RUNNING" ]; then
    restart_network
    tweak_network_file
elif [ "$HOOK" = "VPP_DONE_OK" ]; then
    undo_dns_fix
    remove_tweaked_network_file
    restart_network
elif [ "$HOOK" = "VPP_ERRORED" ]; then
    undo_dns_fix
    remove_tweaked_network_file
    restart_network
fi

EOSCRIPT
