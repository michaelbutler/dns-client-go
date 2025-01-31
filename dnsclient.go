package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"math/rand"

	"github.com/urfave/cli/v2"
)

const RECORD_TYPE_A = 1
const RECORD_TYPE_NS = 2
const RECORD_TYPE_CNAME = 5
const RECORD_TYPE_SOA = 6
const RECORD_TYPE_PTR = 12
const RECORD_TYPE_MX = 15
const RECORD_TYPE_TXT = 16
const RECORD_TYPE_AAAA = 28
const RECORD_TYPE_SRV = 33

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
	Ttl      uint32
	RdLength uint16
	Rdata    []byte // 4 bytes for IPv4 address
	Rendered string // Human readable representation of the Rdata
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
	bytes := make([]byte, 512)
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
	nn := 0
	for i, b := range bytes {
		fmt.Printf("%02x", b)
		g++
		nn++
		if g == max {
			break
		}
		if (i+1)%2 == 0 {
			fmt.Print(" ")
		}
		if nn == 16 {
			fmt.Println("")
			nn = 0
		}
	}
	fmt.Println("")
}

func generateRandomId() uint16 {
	// Generate a random uint16
	random16 := rand.Intn(65535)
	return uint16(random16)
}

// Lookup a Qname label in byte array starting and index start
// Return the label and the new index
// If it's a compressed label, we recursively call this function to grab the label elsewhere
func getLabel(start int, fullbytes []byte) (string, int) {
	b := start
	label := string("")
	chunk := ""
	for {
		if fullbytes[b] == 0x00 {
			b++
			break
		}
		labelStart := fullbytes[b]
		if (labelStart & 0b11000000) == 0b11000000 {
			// Compressed portion
			labelOffset := uint16(labelStart&0b00111111)<<8 | uint16(fullbytes[b+1])
			// basically a 14-bit number pointing to the actual chunk
			chunk, _ = getLabel(int(labelOffset), fullbytes)
			label += string(chunk)
			b += 2 // jump past the 2 bytes pointer and just return
			return label, b
		} else {
			length := int(labelStart)
			chunk = string(fullbytes[b+1 : b+1+length])
			b += length + 1
			label += string(chunk) + "."
		}
	}
	return label, b
}

// Convert the Rdata bytes into a human-readable format
// Usually an IPv4 address, but could be many other things
// We need to pass in the full bytes also, to handle compressed labels pointing to the actual domain name
func getRdataHumanDisplay(bytes []byte, fullbytes []byte, recType uint16, rDataStart int) string {
	if recType == RECORD_TYPE_A {
		return fmt.Sprintf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3])
	}
	if recType == RECORD_TYPE_MX {
		pref := grabUint16(bytes, 0)
		label, _ := getLabel(rDataStart+2, fullbytes)
		return fmt.Sprintf("%d %s", pref, label)
	}
	if recType == RECORD_TYPE_NS || recType == RECORD_TYPE_CNAME || recType == RECORD_TYPE_PTR {
		label, _ := getLabel(rDataStart, fullbytes)
		return label
	}
	if recType == RECORD_TYPE_SOA {
		mName, offset1 := getLabel(rDataStart, fullbytes)
		rName, nextOffset := getLabel(offset1, fullbytes)
		serial := grabUint32(fullbytes, nextOffset)
		refresh := grabUint32(fullbytes, nextOffset+4)
		retry := grabUint32(fullbytes, nextOffset+8)
		expire := grabUint32(fullbytes, nextOffset+12)
		minimum := grabUint32(fullbytes, nextOffset+16)
		return fmt.Sprintf("%s %s %d %d %d %d %d", mName, rName, serial, refresh, retry, expire, minimum)
	}
	// Unknown, return hex representation
	return fmt.Sprintf("%x", bytes)
}

func recordIntToType(recInt uint16) string {
	switch recInt {
	case RECORD_TYPE_A:
		return "A"
	case RECORD_TYPE_NS:
		return "NS"
	case RECORD_TYPE_CNAME:
		return "CNAME"
	case RECORD_TYPE_SOA:
		return "SOA"
	case RECORD_TYPE_PTR:
		return "PTR"
	case RECORD_TYPE_MX:
		return "MX"
	case RECORD_TYPE_TXT:
		return "TXT"
	case RECORD_TYPE_AAAA:
		return "AAAA"
	case RECORD_TYPE_SRV:
		return "SRV"
	default:
		// Return decimal representation for unknown
		return fmt.Sprintf("%d", recInt)
	}
}

func recordTypeToInt(recType string) uint16 {
	switch recType {
	case "A":
		return RECORD_TYPE_A
	case "NS":
		return RECORD_TYPE_NS
	case "CNAME":
		return RECORD_TYPE_CNAME
	case "SOA":
		return RECORD_TYPE_SOA
	case "PTR":
		return RECORD_TYPE_PTR
	case "MX":
		return RECORD_TYPE_MX
	case "TXT":
		return RECORD_TYPE_TXT
	case "AAAA":
		return RECORD_TYPE_AAAA
	case "SRV":
		return RECORD_TYPE_SRV
	default:
		return 0
	}
}

// Helper function to grab a uint32 from a byte array
func grabUint32(bytes []byte, start int) uint32 {
	return uint32(bytes[start])<<24 | uint32(bytes[start+1])<<16 | uint32(bytes[start+2])<<8 | uint32(bytes[start+3])
}

// Helper function to grab a uint16 from a byte array
func grabUint16(bytes []byte, start int) uint16 {
	return uint16(bytes[start])<<8 | uint16(bytes[start+1])
}

func buildResourceRecords(bytes []byte, start int, count int) ([]DnsResourceRecord, int) {
	answers := make([]DnsResourceRecord, count)
	b := start
	for i := 0; i < int(count); i++ {
		label, newOffset := getLabel(b, bytes)
		b = newOffset
		answers[i].Name = label
		answers[i].Type = grabUint16(bytes, b)
		answers[i].Class = grabUint16(bytes, b+2)
		answers[i].Ttl = grabUint32(bytes, b+4)
		answers[i].RdLength = grabUint16(bytes, b+8)
		b += 10
		answers[i].Rdata = bytes[b : b+int(answers[i].RdLength)]
		answers[i].Rendered = getRdataHumanDisplay(answers[i].Rdata, bytes, answers[i].Type, b)
		b += int(answers[i].RdLength)
	}
	return answers, b
}

func decodeAnswerSection(bytes []byte, start int, numAnswers int, label string) int {
	answers, nextOffset := buildResourceRecords(bytes, start, numAnswers)

	if numAnswers > 0 {
		fmt.Println(label, "Section:")

		for _, answer := range answers {
			fmt.Printf("%s\t%d\t%x\t%s\t%s\n", answer.Name, answer.Ttl, answer.Class, recordIntToType(answer.Type), answer.Rendered)
		}
		fmt.Println("-----------------------------------------------------------------")
	}

	return nextOffset
}

func decodeDnsResponse(bytes []byte) DnsMessage {
	// Decode the DNS response
	// The first 12 bytes are the header
	header := DnsHeader{
		Id:      grabUint16(bytes, 0),
		Flags:   grabUint16(bytes, 2),
		QuCount: grabUint16(bytes, 4),
		AnCount: grabUint16(bytes, 6),
		AuCount: grabUint16(bytes, 8),
		AdCount: grabUint16(bytes, 10),
	}

	fmt.Println("-----------------------------------------------------------------")
	fmt.Println("Header Section:")
	fmt.Printf("XID=%x\tFlags=%x\tQuestion=%d\tAnswers=%d\tAuthority=%d\tAdditional=%d\n", header.Id, header.Flags, header.QuCount, header.AnCount, header.AuCount, header.AdCount)
	fmt.Println("-----------------------------------------------------------------")

	domainName, b := getLabel(12, bytes)

	question := DnsQuestion{
		Qname:  domainName,
		Qclass: grabUint16(bytes, b),
		Qtype:  grabUint16(bytes, b+2),
	}
	b += 4

	fmt.Println("Question Section:")
	fmt.Printf("QNAME=%s\tQCLASS=%x\tQTYPE=%x\n", question.Qname, question.Qclass, question.Qtype)
	fmt.Println("-----------------------------------------------------------------")

	// Answer Section
	b = decodeAnswerSection(bytes, b, int(header.AnCount), "Answer")
	// Authority Section
	b = decodeAnswerSection(bytes, b, int(header.AuCount), "Authority")
	// Additional Section
	decodeAnswerSection(bytes, b, int(header.AdCount), "Additional")

	// Print current date and time
	fmt.Printf("WHEN (Local):\t%s\n", time.Now().Format(time.RFC3339Nano))
	utcTime := time.Now().UTC()
	fmt.Printf("WHEN (UTC):\t%s\n", utcTime.Format(time.RFC3339Nano))

	return DnsMessage{}
}

// Rudimentary function to check if a domain name is valid (probably does not catch every case)
func isValidDomain(domain string) bool {
	if len(domain) > 255 {
		return false
	}
	if domain == "" {
		return false
	}
	var domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

func getDnsServer(c *cli.Context) string {
	dnsServer := c.String("dns-server")
	if dnsServer == "" {
		// TODO: read from system DNS settings if blank
		dnsServer = "8.8.8.8" // use Google's public DNS
	}
	return dnsServer
}

func main() {
	app := &cli.App{
		Name:  "dnsclient",
		Usage: "Query DNS records",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "debug",
				Usage: "Enable debug mode, prints raw bytes",
				Value: false,
			},
			&cli.StringFlag{
				Name:  "dns-server",
				Usage: "DNS server to query",
				Value: "",
			},
			&cli.StringFlag{
				Name:  "domain",
				Usage: "Domain name to query",
			},
			&cli.StringFlag{
				Name:  "port",
				Usage: "Port to use for DNS query",
				Value: "53",
			},
			&cli.StringFlag{
				Name:  "type",
				Usage: "Type of DNS record to query",
				Value: "A",
			},
		},
		Action: func(c *cli.Context) error {
			// TODO: Handle case where response is larger than 512 bytes
			p := make([]byte, 512)
			debugMode := c.Bool("debug")
			domain := c.String("domain")
			// Exit if the domain contains invalid characters
			if !isValidDomain(domain) {
				err := fmt.Errorf("ERROR: Invalid domain name: \"%s\"", domain)
				cli.ShowAppHelp(c)
				// Help text gets printed to STDOUT
				// Error text gets printed to STDERR
				return err
			}
			recordType := recordTypeToInt(c.String("type"))
			if recordType == 0 {
				err := fmt.Errorf("ERROR: Invalid record type: \"%s\"", c.String("type"))
				cli.ShowAppHelp(c)
				return err
			}
			dnsServer := getDnsServer(c)
			conn, err := net.Dial("udp", dnsServer+":"+c.String("port"))
			if err != nil {
				return err
			}
			// Send DNS query to the server
			header := DnsHeader{
				Id:      generateRandomId(),
				Flags:   0x0100,
				QuCount: 0x0001,
				AnCount: 0x0000,
				AuCount: 0x0000,
				AdCount: 0x0000,
			}
			question := DnsQuestion{
				Qname:  domain,
				Qclass: 0x0001,     // QCLASS=IN
				Qtype:  recordType, // QTYPE=A
			}
			msg := DnsMessage{
				Header:   header,
				Question: question,
			}
			bytes := encodeMessage(msg)

			if debugMode {
				fmt.Println("Encoded msg:")
				debugPrintBytes(bytes, 128)
			}

			_, err = conn.Write(bytes)
			if err != nil {
				return err
			}

			if debugMode {
				fmt.Println("Wrote to DNS server:", dnsServer+":"+c.String("port"))
			}

			_, err = bufio.NewReader(conn).Read(p)
			if err != nil {
				if debugMode {
					fmt.Println("Error reading from DNS server.")
				}
				return err
			} else if debugMode {
				debugPrintBytes(p, 200)
				fmt.Println("")
			}
			conn.Close()

			decodeDnsResponse(p)

			return nil
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
