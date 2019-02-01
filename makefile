build:
	mkdir -p upx
	rm -rf upx/pcap-udp-forward
	go build
	upx -9 -o upx/pcap-udp-forward pcap-udp-forward
