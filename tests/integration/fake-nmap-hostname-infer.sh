#!/bin/sh
set -eu

TARGET=""

for arg in "$@"; do
    TARGET="$arg"
done

if [ "$TARGET" = "" ]; then
    echo "fake-nmap-hostname-infer: target is missing" >&2
    exit 1
fi

emit_discovery() {
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake discovery no-hostname" start="1712000000" startstr="fake" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.20.30.40" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:40" addrtype="mac" vendor="LabVendor"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port>
    </ports>
  </host>
  <runstats>
    <finished time="1712000001" timestr="fake" elapsed="1.00" summary="Nmap done" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
EOF
}

emit_detail() {
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake detail no-hostname" start="1712000002" startstr="fake" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.20.30.40" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:40" addrtype="mac" vendor="LabVendor"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
        <script id="ssl-cert" output="Subject: commonName=tplinkwifi.net/countryName=CN Not valid before: 2010-01-01"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1712000003" timestr="fake" elapsed="1.00" summary="Nmap done" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
EOF
}

case "$TARGET" in
    */*)
        emit_discovery
        ;;
    10.20.30.40)
        emit_detail
        ;;
    *)
        echo "fake-nmap-hostname-infer: unsupported target '$TARGET'" >&2
        exit 2
        ;;
esac
