build:
	mkdir upx
	go build
	upx -9 -o upx/pcap-udp-forward pcap-udp-forward
