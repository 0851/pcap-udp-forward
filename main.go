package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func logErrorMessage(err interface{}, title string) {
	switch e := err.(type) {
	case gopacket.ErrorLayer:
		log.Printf("[ErrorLayer]: %s | %s", e.Error(), title)
	case error:
		log.Printf("[Error]: %s | %s", e.Error(), title)
	default:

	}
}

func printAllDevice() {
	var ifs []pcap.Interface
	var err error

	ifs, err = pcap.FindAllDevs()

	logErrorMessage(err, "print all devs")

	ifsLen := len(ifs)
	for i := 0; i < ifsLen; i++ {
		item := ifs[i]
		fmt.Printf("name : ")
		fmt.Printf("%s\n", item.Name)
		for n := 0; n < len(item.Addresses); n++ {
			addr := item.Addresses[n]
			fmt.Printf("       ip : %s\n", addr.IP)
			fmt.Printf("       mask : %s\n", addr.Netmask)
		}
	}
}

func forward(source []string, dest []string, filter string) {
	sourceLen := len(source)
	if sourceLen <= 0 {
		log.Println("[Warning]: lose source , usage : -s device name -s device name")
		return
	}
	log.Printf("[Run]: Start forward %s | %s | %s", strings.Join(source, ","), strings.Join(dest, ","), filter)
	for _, s := range source {
		forwardOnePacket(s, dest, filter)
	}
}

func forwardOnePacket(source string, dest []string, filter string) {
	handle, err := pcap.OpenLive(
		source,         // device
		int32(65535),   //	snapshot length
		false,          //	promiscuous mode?
		-1*time.Second, // timeout 负数表示不缓存，直接输出
	)

	defer handle.Close()

	logErrorMessage(err, "open pcap")

	destLen := len(dest)
	if destLen <= 0 {
		log.Println("[Warning]: lose dest , usage : -d ip:port -d ip:port")
		return
	}

	exclude := " and (not ("

	for _, d := range dest {
		da := strings.Split(d, ":")
		host := da[0]
		port := da[1]
		exclude += "dst port " + port + " and dst host " + host + " "
	}

	exclude += " ))"

	f := filter + exclude

	err = handle.SetBPFFilter(f)

	logErrorMessage(err, "set filter")

	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)

	log.Printf("[Catch]:  %s", f)

	for packet := range packetSource.Packets() {
		packetHandle(packet, dest, f)
	}
}
func sendUdp(host string, port string, payload []byte) {
	udpAddr, err := net.ResolveUDPAddr("udp4", host+":"+port)
	logErrorMessage(err, "get udp addr")
	conn, err := net.DialUDP("udp", nil, udpAddr)
	logErrorMessage(err, "create udp")
	defer conn.Close()
	_, err = conn.Write(payload)
	logErrorMessage(err, "write payload")
}
func packetHandle(p gopacket.Packet, dest []string, filter string) {
	udpLayer := p.TransportLayer()
	if udpLayer != nil {
		for _, d := range dest {
			da := strings.Split(d, ":")
			host := da[0]
			port := da[1]
			payload := udpLayer.LayerPayload()
			log.Printf("[Send]:  %s:%s | %s", host, port, filter)
			sendUdp(host, port, payload)
		}
	}
	err := p.ErrorLayer()
	logErrorMessage(err, "pcap error layer")
}

func main() {
	//	获取 libpcap 的版本
	version := pcap.Version()
	log.Println(version)
	app := cli.NewApp()
	app.Name = "pcap-udp-forward"
	app.Usage = "forward packet with udp"
	app.Flags = []cli.Flag{
		cli.StringSliceFlag{
			Name:  "source,s",
			Usage: "source pcap interface name",
		},
		cli.StringFlag{
			Name:  "filter,f",
			Usage: "pcap filter string",
		},
		cli.StringSliceFlag{
			Name:  "dest,d",
			Usage: "destination ip address and port , address:port",
		},
		cli.BoolFlag{
			Name:  "list,l",
			Usage: "show device list",
		},
	}
	app.Action = func(c *cli.Context) error {
		list := c.Bool("list")
		if list {
			printAllDevice()
			return nil
		}

		source := c.StringSlice("source")
		dest := c.StringSlice("dest")
		filter := c.String("filter")

		forward(source, dest, filter)

		return nil
	}
	err := app.Run(os.Args)

	logErrorMessage(err, "start error")
}
