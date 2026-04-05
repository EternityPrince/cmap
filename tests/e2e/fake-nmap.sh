#!/bin/sh
set -eu

ROUND=${CMAPER_FAKE_ROUND:-1}
TARGET=""

for arg in "$@"; do
    TARGET="$arg"
done

if [ "$TARGET" = "" ]; then
    echo "fake-nmap: target is missing" >&2
    exit 1
fi

emit_discovery_round_1() {
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake discovery round1" start="1710000000" startstr="fake" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:01" addrtype="mac" vendor="LabVendor"/>
    <hostnames><hostname name="core-01.lab" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port>
    </ports>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.20" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:02" addrtype="mac" vendor="LabVendor"/>
    <hostnames><hostname name="win-edge.lab" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds"/></port>
    </ports>
  </host>
  <runstats>
    <finished time="1710000001" timestr="fake" elapsed="1.00" summary="Nmap done" exit="success"/>
    <hosts up="2" down="0" total="2"/>
  </runstats>
</nmaprun>
EOF
}

emit_discovery_round_2() {
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake discovery round2" start="1710000100" startstr="fake" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:01" addrtype="mac" vendor="LabVendor"/>
    <hostnames><hostname name="core-01.lab" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh"/></port>
      <port protocol="tcp" portid="8443"><state state="open" reason="syn-ack"/><service name="https"/></port>
    </ports>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.30" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:02" addrtype="mac" vendor="LabVendor"/>
    <hostnames><hostname name="win-edge-new.lab" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds"/></port>
      <port protocol="tcp" portid="3389"><state state="open" reason="syn-ack"/><service name="ms-wbt-server"/></port>
    </ports>
  </host>
  <runstats>
    <finished time="1710000101" timestr="fake" elapsed="1.00" summary="Nmap done" exit="success"/>
    <hosts up="2" down="0" total="2"/>
  </runstats>
</nmaprun>
EOF
}

emit_detail_10_round_1() {
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake detail 10 round1" start="1710000002" startstr="fake" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:01" addrtype="mac" vendor="LabVendor"/>
    <hostnames><hostname name="core-01.lab" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
        <script id="ssh-hostkey" output="ssh-ed25519 256 SHA256:abc123fake"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
        <script id="http-title" output="Title: Core Dashboard"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1710000003" timestr="fake" elapsed="1.00" summary="Nmap done" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
EOF
}

emit_detail_10_round_2() {
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake detail 10 round2" start="1710000102" startstr="fake" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:01" addrtype="mac" vendor="LabVendor"/>
    <hostnames><hostname name="core-01.lab" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
        <script id="ssh-hostkey" output="ssh-ed25519 256 SHA256:def456fake"/>
      </port>
      <port protocol="tcp" portid="8443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
        <script id="http-title" output="Title: Kubernetes API"/>
        <script id="vuln" output="CVE-2026-9999 vulnerable high"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1710000103" timestr="fake" elapsed="1.00" summary="Nmap done" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
EOF
}

emit_detail_20_round_1() {
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake detail 20 round1" start="1710000004" startstr="fake" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.20" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:02" addrtype="mac" vendor="LabVendor"/>
    <hostnames><hostname name="win-edge.lab" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds"/>
        <script id="smb-os-discovery" output="OS: Windows Server 2019"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1710000005" timestr="fake" elapsed="1.00" summary="Nmap done" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
EOF
}

emit_detail_30_round_2() {
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake detail 30 round2" start="1710000104" startstr="fake" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.30" addrtype="ipv4"/>
    <address addr="02:42:ac:11:00:02" addrtype="mac" vendor="LabVendor"/>
    <hostnames><hostname name="win-edge-new.lab" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds"/>
        <script id="smb-os-discovery" output="OS: Windows Server 2022"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open" reason="syn-ack"/>
        <service name="ms-wbt-server"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1710000105" timestr="fake" elapsed="1.00" summary="Nmap done" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
EOF
}

case "$TARGET" in
    */*)
        if [ "$ROUND" = "1" ]; then
            emit_discovery_round_1
        else
            emit_discovery_round_2
        fi
        ;;
    10.0.0.10)
        if [ "$ROUND" = "1" ]; then
            emit_detail_10_round_1
        else
            emit_detail_10_round_2
        fi
        ;;
    10.0.0.20)
        emit_detail_20_round_1
        ;;
    10.0.0.30)
        emit_detail_30_round_2
        ;;
    *)
        echo "fake-nmap: unsupported target '$TARGET'" >&2
        exit 2
        ;;
esac
