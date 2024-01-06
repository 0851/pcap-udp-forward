# pcap-udp-forward

> filter use [bpf](https://biot.com/capstats/bpf.html) 
```bash
过滤IP： 10.1.1.3
过滤CIDR： 128.3/16
过滤端口： port 53
过滤主机和端口： host 8.8.8.8 and udp port 53
过滤网段和端口： net 199.16.156.0/22 and port
过滤非本机 Web 流量： (port 80 and port 443) and not host 192.168.0.1
```

```bash
NAME:
   pcap-udp-forward - forward packet with udp

USAGE:
   main [global options] command [command options] [arguments...]

VERSION:
   0.0.0

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --source value, -s value  source pcap interface name
   --filter value, -f value  pcap filter string
   --dest value, -d value    destination ip address and port , address:port
   --list, -l                show device list
   --help, -h                show help
   --version, -v             print the version

```
## build
```bash
make build
```
## example

```bash
#添加执行权限
chmod +x pcap-udp-forward
#获取所有网卡设备
./pcap-udp-forward -l
#执行
./pcap-udp-forward -s eth0 -f "udp port 57" -d 127.0.0.1:8080 -d 127.0.0.1:9000

```
