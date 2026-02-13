#!/bin/sh

HOOK="$0"
INTERFACE_NAME="$1"
chroot /host /bin/sh -s "$HOOK" "$INTERFACE_NAME" <<'EOSCRIPT'
HOOK="$1"
INTERFACE_NAME="$2"

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
        systemctl restart systemd-udev-trigger
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

capture_udev_net_name_properties () {
  echo "default_hook: Capturing udev net name properties for $INTERFACE_NAME..."

  UDEV_INFO=$(udevadm info /sys/class/net/$INTERFACE_NAME 2>/dev/null)
  if [ -z "$UDEV_INFO" ]; then
    echo "default_hook: Failed to get udevadm info for $INTERFACE_NAME"
    return
  fi

  # Extract ID_NET_NAME_* properties
  ID_NET_NAME_ONBOARD=$(echo "$UDEV_INFO" | grep "ID_NET_NAME_ONBOARD=" | sed 's/.*ID_NET_NAME_ONBOARD=//')
  ID_NET_NAME_SLOT=$(echo "$UDEV_INFO" | grep "ID_NET_NAME_SLOT=" | sed 's/.*ID_NET_NAME_SLOT=//')
  ID_NET_NAME_PATH=$(echo "$UDEV_INFO" | grep "ID_NET_NAME_PATH=" | sed 's/.*ID_NET_NAME_PATH=//')
  ID_NET_NAME_MAC=$(echo "$UDEV_INFO" | grep "ID_NET_NAME_MAC=" | sed 's/.*ID_NET_NAME_MAC=//')

  # Check if we have any properties to save
  if [ -z "$ID_NET_NAME_ONBOARD" ] && [ -z "$ID_NET_NAME_SLOT" ] && [ -z "$ID_NET_NAME_PATH" ] && [ -z "$ID_NET_NAME_MAC" ]; then
    echo "default_hook: No udev net name properties found for $INTERFACE_NAME"
    return
  fi

  # Get MAC address
  MAC_ADDRESS=$(cat /sys/class/net/$INTERFACE_NAME/address 2>/dev/null)
  if [ -z "$MAC_ADDRESS" ]; then
    echo "default_hook: Failed to get MAC address for $INTERFACE_NAME"
    return
  fi

  # Save properties to temp file for later use
  mkdir -p /var/run/vpp
  echo "MAC_ADDRESS=$MAC_ADDRESS" > /var/run/vpp/udev_props_$INTERFACE_NAME
  [ -n "$ID_NET_NAME_ONBOARD" ] && echo "ID_NET_NAME_ONBOARD=$ID_NET_NAME_ONBOARD" >> /var/run/vpp/udev_props_$INTERFACE_NAME
  [ -n "$ID_NET_NAME_SLOT" ] && echo "ID_NET_NAME_SLOT=$ID_NET_NAME_SLOT" >> /var/run/vpp/udev_props_$INTERFACE_NAME
  [ -n "$ID_NET_NAME_PATH" ] && echo "ID_NET_NAME_PATH=$ID_NET_NAME_PATH" >> /var/run/vpp/udev_props_$INTERFACE_NAME
  [ -n "$ID_NET_NAME_MAC" ] && echo "ID_NET_NAME_MAC=$ID_NET_NAME_MAC" >> /var/run/vpp/udev_props_$INTERFACE_NAME

  echo "default_hook: Captured udev properties for $INTERFACE_NAME (MAC: $MAC_ADDRESS)"
  [ -n "$ID_NET_NAME_ONBOARD" ] && echo "default_hook: ID_NET_NAME_ONBOARD=$ID_NET_NAME_ONBOARD"
  [ -n "$ID_NET_NAME_SLOT" ] && echo "default_hook: ID_NET_NAME_SLOT=$ID_NET_NAME_SLOT"
  [ -n "$ID_NET_NAME_PATH" ] && echo "default_hook: ID_NET_NAME_PATH=$ID_NET_NAME_PATH"
  [ -n "$ID_NET_NAME_MAC" ] && echo "default_hook: ID_NET_NAME_MAC=$ID_NET_NAME_MAC"
}

install_udev_net_name_rule () {
  PROPS_FILE="/var/run/vpp/udev_props_$INTERFACE_NAME"
  if [ ! -f "$PROPS_FILE" ]; then
    echo "default_hook: No udev properties captured for $INTERFACE_NAME, skipping rule installation"
    return
  fi

  # Source the properties file
  . "$PROPS_FILE"

  if [ -z "$MAC_ADDRESS" ]; then
    echo "default_hook: No MAC address captured for $INTERFACE_NAME, skipping rule installation"
    return
  fi

  echo "default_hook: Installing udev rule for $INTERFACE_NAME with MAC $MAC_ADDRESS..."

  # Build the udev rule.
  # This rule must be in place BEFORE VPP creates the host-facing tap so that
  # udev re-applies the original ID_NET_NAME_* properties on net events
  # (initial add and subsequent change/move re-evaluations). systemd-networkd
  # uses these properties (via net_get_persistent_name) to compute a stable
  # DHCPv6 IAID; without them the IAID is derived from the MAC address, which
  # differs from the IAID computed for the physical NIC.
  RULE_FILE="/etc/udev/rules.d/99-vpp-restore-id_net_name.rules"
  echo "# Re-apply ID_NET_NAME_* properties after Calico VPP creates the host-facing tap/tun netdev." > "$RULE_FILE"
  printf 'SUBSYSTEM=="net", ATTR{address}=="%s"' "$MAC_ADDRESS" >> "$RULE_FILE"

  [ -n "$ID_NET_NAME_ONBOARD" ] && printf ', ENV{ID_NET_NAME_ONBOARD}:="%s"' "$ID_NET_NAME_ONBOARD" >> "$RULE_FILE"
  [ -n "$ID_NET_NAME_SLOT" ] && printf ', ENV{ID_NET_NAME_SLOT}:="%s"' "$ID_NET_NAME_SLOT" >> "$RULE_FILE"
  [ -n "$ID_NET_NAME_PATH" ] && printf ', ENV{ID_NET_NAME_PATH}:="%s"' "$ID_NET_NAME_PATH" >> "$RULE_FILE"
  [ -n "$ID_NET_NAME_MAC" ] && printf ', ENV{ID_NET_NAME_MAC}:="%s"' "$ID_NET_NAME_MAC" >> "$RULE_FILE"

  echo "" >> "$RULE_FILE"

  echo "default_hook: Installed udev rule file at $RULE_FILE"

  # Reload udev rules so the new rule is active for subsequent net events.
  udevadm control --reload-rules
  echo "default_hook: Reloaded udev rules"
}

remove_udev_net_name_rule () {
  RULE_FILE="/etc/udev/rules.d/99-vpp-restore-id_net_name.rules"
  PROPS_FILE="/var/run/vpp/udev_props_$INTERFACE_NAME"

  if [ -f "$RULE_FILE" ]; then
    echo "default_hook: Removing udev rule file $RULE_FILE..."
    rm -f "$RULE_FILE"
    udevadm control --reload-rules

    # Trigger udev for net subsystem to remove the stored ID_NET_NAME_* properties
    udevadm trigger --subsystem-match=net --action=change
    echo "default_hook: Triggered udev to remove the stored ID_NET_NAME_* properties"
  fi

  if [ -f "$PROPS_FILE" ]; then
    rm -f "$PROPS_FILE"
  fi
}

echo "default_hook: Uplink interface name=$INTERFACE_NAME"
if which systemctl > /dev/null; then
    echo "default_hook: using systemctl..."
else
    echo "default_hook: Init system not supported, network configuration may fail"
    exit 1
fi

if [ "$HOOK" = "BEFORE_IF_READ" ]; then
    capture_udev_net_name_properties
elif [ "$HOOK" = "BEFORE_VPP_RUN" ]; then
    fix_dns
    install_udev_net_name_rule
    save_network_file
elif [ "$HOOK" = "VPP_RUNNING" ]; then
    restart_network
    tweak_network_file
elif [ "$HOOK" = "VPP_DONE_OK" ]; then
    undo_dns_fix
    remove_udev_net_name_rule
    remove_tweaked_network_file
    restart_network
elif [ "$HOOK" = "VPP_ERRORED" ]; then
    undo_dns_fix
    remove_udev_net_name_rule
    remove_tweaked_network_file
    restart_network
fi

EOSCRIPT
