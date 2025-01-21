package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
)

type DnsHeader struct {
	Id      uint16
	Flags   uint16
	QuCount uint16 // Question count
	AnCount uint16 // Answer count
	AuCount uint16 // Authority count
	AdCount uint16 // Additional count
}

type DnsQuestion struct {
	Qname  string
	Qclass uint16
	Qtype  uint16
}

type DnsResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	Ttl      uint16
	RdLength uint16
	Rdata    string
}

type DnsMessage struct {
	Header     DnsHeader
	Question   DnsQuestion
	Answer     DnsResourceRecord
	Authority  DnsResourceRecord
	Additional DnsResourceRecord
}

// Encode a domain name into a byte array
// The domain name is like "www.yahoo.com", a regular string with dots separating the parts
func encodeQname(qname string) []byte {
	bytes := make([]byte, 0)
	labels := strings.Split(qname, ".")
	for _, label := range labels {
		// First byte is the length of the label
		// So for "www", the first byte is 0x03 (3 in decimal)
		bytes = append(bytes, byte(len(label)))
		for _, c := range label {
			bytes = append(bytes, byte(c))
		}
	}
	// The last byte is 0x00 to indicate the end of the Qname portion
	bytes = append(bytes, 0x00)
	return bytes
}

func encodeMessage(msg DnsMessage) []byte {
	bytes := make([]byte, 2048)
	bytes[0] = byte(msg.Header.Id >> 8)
	bytes[1] = byte(msg.Header.Id)
	bytes[2] = byte(msg.Header.Flags >> 8)
	bytes[3] = byte(msg.Header.Flags)
	bytes[4] = byte(msg.Header.QuCount >> 8)
	bytes[5] = byte(msg.Header.QuCount)
	bytes[6] = byte(msg.Header.AnCount >> 8)
	bytes[7] = byte(msg.Header.AnCount)
	bytes[8] = byte(msg.Header.AuCount >> 8)
	bytes[9] = byte(msg.Header.AuCount)
	bytes[10] = byte(msg.Header.AdCount >> 8)
	bytes[11] = byte(msg.Header.AdCount)

	// example.com => 0765 7861 6d70 6c65 0363 6f6d 00
	qnameBytes := encodeQname(msg.Question.Qname)
	x := 12

	for _, b := range qnameBytes {
		bytes[x] = b
		x++
	}

	bytes[x] = byte(msg.Question.Qtype >> 8)
	x++
	bytes[x] = byte(msg.Question.Qtype)
	x++
	bytes[x] = byte(msg.Question.Qclass >> 8)
	x++
	bytes[x] = byte(msg.Question.Qclass)

	// Return the bytes slice with the correct length
	return bytes[:x+1]
}

func debugPrintBytes(bytes []byte, max int) {
	g := 0
	for i, b := range bytes {
		fmt.Printf("%02x", b)
		g++
		if g == max {
			break
		}
		if (i+1)%2 == 0 {
			fmt.Print(" ")
		}
	}
	fmt.Println("")
}

func main() {
	app := &cli.App{
		Name:  "dnsclient",
		Usage: "Query DNS records",
		Action: func(c *cli.Context) error {
			p := make([]byte, 512)
			fmt.Println("Running UDP Dial")
			conn, err := net.Dial("udp", "8.8.8.8:53")
			if err != nil {
				return err
			}
			fmt.Println("Writing data to conn")
			// Send DNS query to the server
			header := DnsHeader{
				Id:      0xABAB,
				Flags:   0x0100,
				QuCount: 0x0001,
				AnCount: 0x0000,
				AuCount: 0x0000,
				AdCount: 0x0000,
			}
			question := DnsQuestion{
				Qname:  "example.com",
				Qclass: 0x0001, // QCLASS=IN
				Qtype:  0x0001, // QTYPE=A
			}
			msg := DnsMessage{
				Header:   header,
				Question: question,
			}
			bytes := encodeMessage(msg)

			fmt.Println("Encoded msg:")
			debugPrintBytes(bytes, 128)

			_, err = conn.Write(bytes)
			if err != nil {
				return err
			}
			fmt.Println("Reading response:")
			_, err = bufio.NewReader(conn).Read(p)
			fmt.Println("Printing the result as raw hexadecimal:")
			if err != nil {
				return err
			} else {
				// Print p in hexadecimal
				debugPrintBytes(p, 200)
				fmt.Println("")
			}
			conn.Close()
			return nil
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
