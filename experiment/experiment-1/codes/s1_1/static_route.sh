echo "Set route s1_1"
route add -net 10.4.1.0 netmask 255.255.255.0 gw 10.1.1.2
service haproxy restart
bash