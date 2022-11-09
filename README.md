# How-to-set-up-v2ray-directly-in-openwrt

## My openwrt version

```
#cat /etc/os-release

NAME="OpenWrt"
VERSION="22.03.0"
ID="openwrt"
ID_LIKE="lede openwrt"
PRETTY_NAME="OpenWrt 22.03.0"
VERSION_ID="22.03.0"
HOME_URL="https://openwrt.org/"
BUG_URL="https://bugs.openwrt.org/"
SUPPORT_URL="https://forum.openwrt.org/"
BUILD_ID="r19685-512e76967f"
OPENWRT_BOARD="ramips/mt7621"
OPENWRT_ARCH="mipsel_24kc"
OPENWRT_TAINTS=""
OPENWRT_DEVICE_MANUFACTURER="OpenWrt"
OPENWRT_DEVICE_MANUFACTURER_URL="https://openwrt.org/"
OPENWRT_DEVICE_PRODUCT="Generic"
OPENWRT_DEVICE_REVISION="v0"
OPENWRT_RELEASE="OpenWrt 22.03.0 r19685-512e76967f"
```

## Step -1: open a wifi access point, which is typically a wifi hotspot

So that you could connect it through WiFi.

And that's the whole point: create a VPN WiFi.

## Step 0: install some tools

```
opkg update
opkg install curl vim-full iptables iptables-mod-extra ipset kmod-ipt-ipopt iptables-mod-ipopt iptables-mod-tproxy

cp /usr/bin/vim /bin/vi
```

## Step 1: install v2ray

```
opkg install v2ray-core
```

> do a little test: `/usr/bin/v2ray version`

> you should see:

    ```
    V2Ray 5.1.0 (V2Fly, a community-driven edition of V2Ray.) OpenWrt (go1.18.4 linux/mipsle)
    A unified platform for anti-censorship.
    ```

## Step 2: copy `geoip.dat` and `geosite.dat` from your local machine into router `/usr/bin` folder

```
scp ge* root@192.168.1.1:/usr/bin/
```

## Step 3: write v2ray configuration file

```
vim /root/v2ray_config.json
```

file content:

```
{
  "dns": {
    "hosts": {
      "domain:googleapis.cn": "googleapis.com"
    },
    "servers": [
      "1.1.1.1",
      {
        "address": "223.5.5.5",
        "domains": [
          "geosite:cn"
        ],
        "expectIPs": [
          "geoip:cn"
        ],
        "port": 53
      }
    ]
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": true
      },
      "tag": "socks"
    },
    {
      "listen": "0.0.0.0",
      "port": 10809,
      "protocol": "http",
      "settings": {
        "userLevel": 8
      },
      "tag": "http"
    },
    {
      "port": 12345, // The open port that receives traffic
      "protocol": "dokodemo-door",
      "settings": {
        "network": "tcp,udp",
        "followRedirect": true // Need to be set as true to accept traffic from iptables
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "log": {
    "loglevel": "warning"
  },
  "outbounds": [
    {
      "mux": {
        "concurrency": 8,
        "enabled": false
      },
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": "144.202.209.163",
            "port": 1310,
            "users": [
              {
                "alterId": 0,
                "encryption": "",
                "flow": "",
                "id": "fe796f9d-8e99-47a2-b30f-254d11337dc6",
                "level": 8,
                "security": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "",
        "wsSettings": {
          "headers": {
            "Host": ""
          },
          "path": ""
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "policy": {
    "levels": {
      "8": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "routing": {
    "domainMatcher": "mph",
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "ip": [
          "1.1.1.1"
        ],
        "outboundTag": "proxy",
        "port": "53",
        "type": "field"
      },
      {
        "ip": [
          "223.5.5.5"
        ],
        "outboundTag": "direct",
        "port": "53",
        "type": "field"
      },
      {
        "domain": [
          "domain:googleapis.cn"
        ],
        "outboundTag": "proxy",
        "type": "field"
      },
      {
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "direct",
        "type": "field"
      },
      {
        "ip": [
          "geoip:cn"
        ],
        "outboundTag": "direct",
        "type": "field"
      },
      {
        "domain": [
          "geosite:cn"
        ],
        "outboundTag": "direct",
        "type": "field"
      }
    ]
  },
  "stats": {}
}
```

## Step 4: Run it on the background

```
/usr/bin/v2ray run --config=/root/v2ray_config.json &
```

## Step 4.5: Use iptables if it is working (Optional)

For some reason, `iptables` not fully work on this router, it will say `--to-ports` is not defined if I run the following command:

```
sysctl -w net.ipv4.ip_forward=1 # forward any unrelated traffic somewhere, if the system isn't supposed to be forwarding

iptables -t nat -N V2RAY # Create a new chain called V2RAY
iptables -t nat -A V2RAY -d 192.168.0.0/16 -j RETURN # Direct connection 192.168.0.0/16
iptables -t nat -A V2RAY -p tcp -j RETURN -m mark --mark 0xff # Directly connect SO_MARK to 0xff traffic (0xff is a hexadecimal number, numerically equivalent to 255), the purpose of this rule is to avoid proxy loopback with local (gateway) traffic
iptables -t nat -A V2RAY -p tcp -j REDIRECT --to-ports 12345 # The rest of the traffic is forwarded to port 12345 (ie V2Ray)

iptables -t nat -A PREROUTING -p tcp -j V2RAY # Transparent proxy for other LAN devices
iptables -t nat -A OUTPUT -p tcp -j V2RAY # Transparent proxy for this machine
```

```
#iptables -t nat -A PREROUTING -s 192.168.1.0/24 -p tcp -j REDIRECT --to-ports 10808
#iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1:12345
```

> iptables rule will ge canceled when reboot, so don't worry to mass it up. You might need a script or anything (such as `iptables-persistent`) that can automatically load the above iptable rules after the transparent proxy device reboots.

More info about iptables:
https://guide.v2fly.org/en_US/app/transparent_proxy.html#procedures

## Step 5: Set up a firewall rule to forward data into `dokodemo-door` inbound port

set up:

```
uci add firewall redirect
uci set firewall.@redirect[0].target='DNAT'
uci set firewall.@redirect[0].name='Redirect-HTTPS-to-v2ray-dokodemo-door-proxy-port'
uci set firewall.@redirect[0].proto='tcp'
uci set firewall.@redirect[0].src='lan'
uci set firewall.@redirect[0].src_dport='0-65535'
uci set firewall.@redirect[0].dest_port='12345'
uci commit firewall
fw4 restart
```

cancel:

```
uci delete firewall.@redirect[0]
uci commit firewall
fw4 restart
```

show firewall rules:

```
uci show firewall
uci show firewall.@redirect[0]
```

> The above code does this: forward all https traffic from LAN into the `0.0.0.0:12345`.
> (the v2ray config will make sure it won't include some address like `192.168.1.1`, `127.0.0.1`.

> We used to use `redsocks` to forward data into a `socks5` inbound port. It still does the work under a full-linux system.

## Step 6:

So far, you could already have a VPN wifi, enjoy it.

## More config

You could actually make the v2ray auto start at the boot time, one way is to use crontab (it doesn't work on my machine for somehow):

```
#crontab -e
/usr/bin/v2ray run --config=/root/v2ray_config.json
```

Another way is to create a `/etc/init.d` service by yourself, which can be hard for beginners. An example would be: `/etc/init.d/network`
