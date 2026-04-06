#!/bin/sh
set -eu

TARGET=""
HAS_TOP_PORTS=0
PORTS_ARG=""
EXPECT_VALUE=""

for arg in "$@"; do
    if [ "$EXPECT_VALUE" = "ports" ]; then
        PORTS_ARG="$arg"
        EXPECT_VALUE=""
        continue
    fi
    if [ "$EXPECT_VALUE" = "top_ports" ]; then
        EXPECT_VALUE=""
        continue
    fi

    case "$arg" in
        -p)
            EXPECT_VALUE="ports"
            continue
            ;;
        --top-ports)
            HAS_TOP_PORTS=1
            EXPECT_VALUE="top_ports"
            continue
            ;;
    esac

    TARGET="$arg"
done

if [ "$TARGET" = "" ]; then
    echo "fake-nmap-probe-expand: target is missing" >&2
    exit 1
fi

emit_host_with_22() {
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake host-22" start="1711000000" startstr="fake" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:10" addrtype="mac" vendor="LabVendor"/>
    <hostnames><hostname name="expand-test.lab" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh"/></port>
    </ports>
  </host>
  <runstats>
    <finished time="1711000001" timestr="fake" elapsed="1.00" summary="Nmap done" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
EOF
}

emit_host_with_22_80() {
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake host-22-80" start="1711000000" startstr="fake" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:10" addrtype="mac" vendor="LabVendor"/>
    <hostnames><hostname name="expand-test.lab" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
        <script id="ssh-hostkey" output="ssh-ed25519 256 SHA256:expandfake"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
        <script id="http-title" output="Title: Expansion Test"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1711000001" timestr="fake" elapsed="1.00" summary="Nmap done" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
EOF
}

case "$TARGET" in
    */*)
        emit_host_with_22
        ;;
    10.0.0.10)
        if [ "$HAS_TOP_PORTS" -eq 1 ]; then
            emit_host_with_22_80
            exit 0
        fi
        case "$PORTS_ARG" in
            22,80|80,22)
                emit_host_with_22_80
                ;;
            *)
                emit_host_with_22
                ;;
        esac
        ;;
    *)
        echo "fake-nmap-probe-expand: unsupported target '$TARGET'" >&2
        exit 2
        ;;
esac
