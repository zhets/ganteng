#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(curl -sS ipv4.icanhazip.com);
domain=$(cat /root/domain)
MYIP2="s/xxxxxxxxx/$domain/g";
function ovpn_install() {
rm -rf /etc/openvpn
mkdir -p /etc/openvpn
wget -O /etc/openvpn/vpn.zip "https://raw.githubusercontent.com/zhets/ganteng/main/install/openvpn.zip" >/dev/null 2>&1
unzip -d /etc/openvpn/ /etc/openvpn/vpn.zip
rm -f /etc/openvpn/vpn.zip
chown -R root:root /etc/openvpn/server/easy-rsa/
}
function config_easy() {
cd
mkdir -p /usr/lib/openvpn/
cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so
sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn
systemctl enable --now openvpn-server@server-tcp
systemctl enable --now openvpn-server@server-udp
/etc/init.d/openvpn restart
}
cat >/usr/bin/xdxl <<-END
#!/bin/bash
# //            🇵🇸 FREE PALESTINE 🇵🇸
# //                  🇮🇱 IS 🐷
# // ——————————————————————————————
# // Auto delete trial by XDXL STORE 🇮🇩
# // My Telegram: t.me/xdxl_store
# // My Channel: t.me/xdx_vpn
# // Telegram Group: t.me/GrupConfigId
# // Setup 1 for 1 minutes
# // Delete trial with cron
# // ——————————————————————————————

user="$2"

function ssh(){
getent passwd ${user}
userdel -rf ${user}
sed -i "/^#ssh# $user/d" /etc/ssh/.ssh.db
systemctl restart ws-dropbear ws-stunnel
}
function trojan(){
exp=$(grep -wE "^### $user" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^### $user $exp/,/^},{/d" /etc/trojan/.trojan.db
sed -i "/^#! $user $exp/,/^},{/d" /etc/xray/config.json
systemctl restart ws
}

function vmess(){
exp=$(grep -wE "^### $user" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^### $user $exp/,/^},{/d" /etc/xray/config.json
sed -i "/^### $user $exp/,/^},{/d" /etc/vmess/.vmess.db
systemctl restart xray
}

function vless(){
exp=$(grep -wE "^#& $user" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^#& $user $exp/,/^},{/d" /etc/xray/config.json
sed -i "/^#& $user $exp/,/^},{/d" /etc/vless/.vless.db
systemctl restart xray
}

function noobzvpns() {
noobzvpns --remove-user ${user}
rm -rf /var/www/html/noobzvpns-${user}.txt
systemctl restart noobzvpns
}

if [[ ${1} == "ssh" ]]; then
ssh
elif [[ ${1} == "vmess" ]]; then
vmess
elif [[ ${1} == "vless" ]]; then
vless
elif [[ ${1} == "trojan" ]]; then
trojan
elif [[ ${1} == "noobzvpns" ]]; then
noobzvpns
fi
END
function make_follow() {
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
cat > /etc/openvpn/tcp.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 1194
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
sed -i $MYIP2 /etc/openvpn/tcp.ovpn;
cat > /etc/openvpn/udp.ovpn <<-END
client
dev tun
proto udp
remote xxxxxxxxx 2200
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
sed -i $MYIP2 /etc/openvpn/udp.ovpn;
cat > /etc/openvpn/ws-ssl.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 443
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
sed -i $MYIP2 /etc/openvpn/ws-ssl.ovpn;
cat > /etc/openvpn/ssl.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 443
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
sed -i $MYIP2 /etc/openvpn/ssl.ovpn;
}
function cert_ovpn() {
echo '<ca>' >> /etc/openvpn/tcp.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/tcp.ovpn
echo '</ca>' >> /etc/openvpn/tcp.ovpn
cp /etc/openvpn/tcp.ovpn /home/vps/public_html/tcp.ovpn
echo '<ca>' >> /etc/openvpn/udp.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/udp.ovpn
echo '</ca>' >> /etc/openvpn/udp.ovpn
cp /etc/openvpn/udp.ovpn /home/vps/public_html/udp.ovpn
echo '<ca>' >> /etc/openvpn/ws-ssl.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/ws-ssl.ovpn
echo '</ca>' >> /etc/openvpn/ws-ssl.ovpn
cp /etc/openvpn/ws-ssl.ovpn /home/vps/public_html/ws-ssl.ovpn
echo '</ca>' >> /etc/openvpn/ssl.ovpn
cp /etc/openvpn/ws-ssl.ovpn /home/vps/public_html/ssl.ovpn
cd /home/vps/public_html/
zip all-ovpn.zip tcp.ovpn udp.ovpn ssl.ovpn ws-ssl.ovpn > /dev/null 2>&1
cd
cat <<'mySiteOvpn' > /home/vps/public_html/index.html
<!DOCTYPE html>
<html lang="en">
<!-- Simple OVPN Download site -->
<head><meta charset="utf-8" /><title>OVPN Config Download</title><meta name="description" content="Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group">
<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="https://IP-ADDRESSS:81/tcp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>
<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>UDP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="https://IP-ADDRESSS:81/udp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>
<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>SSL <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="https://IP-ADDRESSS:81/ssl.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>
<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p> WS SSL <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="https://IP-ADDRESSS:81/ws-ssl.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>
<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p> ALL.zip <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="https://IP-ADDRESSS:81/all-vpn.zip" style="float:right;"><i class="fa fa-download"></i> Download</a></li>
</ul></div></div></div></div></body></html>
mySiteOvpn
sed -i "s|IP-ADDRESSS|$(curl -sS ifconfig.me)|g" /home/vps/public_html/index.html
}
function install_ovpn() {
ovpn_install
config_easy
make_follow
make_follow
cert_ovpn
systemctl enable openvpn
systemctl start openvpn
/etc/init.d/openvpn restart
}
install_ovpn
