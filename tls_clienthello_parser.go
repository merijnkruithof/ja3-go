package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// greaseBitmask ensures that we'll skip all GREASE extensions. These extensions are skipped because they contain
	// randomized values that shouldn't exist within the fingerprint.
	greaseBitmask uint16 = 0x0F0F

	sniExtensionType    uint16 = 0
	supportedGroupsType uint16 = 10
	ecpfExtensionType   uint16 = 11
)

// ParsedClientHello contains a list of ClientHello data we'll need for the JA3 hash, such as SSLVersion,Cipher
// ,SSLExtension,EllipticCurve, and EllipticCurvePointFormat.
type ParsedClientHello struct {
	TLSVersion struct {
		// Major contains the TLS version. It's always 0x3, or 3, because of its predecessor SSL.
		Major byte

		// Minor contains the current TLS version. "0" is SSL, "1" is TLS version 1.0, and so on.
		Minor byte
	}

	// CipherSuites contains a list with cipher suites that the client is supporting.
	CipherSuites []uint16

	Compression struct {
		Method byte
		Type   byte
	}

	Extensions []uint16

	// SNI (Server Name Indicator) contains the hostname. We'll only accept DNS requests for our JA3 fingerprint.
	SNI []byte

	EllipticCurves                 []uint16
	EllipticCurveCompressionFormat []uint8
}

func ParseClientHello(clientHello string) (parsedClientHello ParsedClientHello, err error) {
	clientHelloBytes, err := hex.DecodeString(clientHello)
	if err != nil {
		return ParsedClientHello{}, err
	}

	buf := bytes.NewBuffer(clientHelloBytes)
	header, err := buf.ReadByte()
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("unable to read client hello packet: %s", err.Error())
	}

	if header != 0x01 {
		return ParsedClientHello{}, fmt.Errorf("not a client hello packet, got %x", header)
	}

	fmt.Println("got client hello")

	handshakeHeader := make([]byte, 3)
	_, err = buf.Read(handshakeHeader)
	if err != nil {
		return ParsedClientHello{}, err
	}

	// Check if 00 00 f4 (0xf4) actually translates to 244 bytes.
	handshakeLength := int(handshakeHeader[0])<<16 | int(handshakeHeader[1])<<8 | int(handshakeHeader[2])

	// we actually don't really care about anything else except the clienthello packet, so we'll just read
	// those bytes and temporarily create a new byte buffer instead of re-using the old one. this will be refactored
	// later to avoid GC pressure.
	clientHelloPacket := make([]byte, handshakeLength)
	_, err = buf.Read(clientHelloPacket)
	if err != nil {
		return ParsedClientHello{}, err
	}

	clientHelloBuf := bytes.NewBuffer(clientHelloPacket)

	tlsMajorVersion, err := clientHelloBuf.ReadByte()
	if err != nil {
		return ParsedClientHello{}, err
	}

	tlsMinorVersion, err := clientHelloBuf.ReadByte()
	if err != nil {
		return ParsedClientHello{}, err
	}

	parsedClientHello.TLSVersion.Major = tlsMajorVersion
	parsedClientHello.TLSVersion.Minor = tlsMinorVersion

	fmt.Println("Got TLS version", parsedClientHello.TLSVersion)

	// read client random
	clientRandom := make([]byte, 32)
	n, err := clientHelloBuf.Read(clientRandom)
	if err != nil {
		return ParsedClientHello{}, err
	}

	if n != cap(clientRandom) {
		return ParsedClientHello{}, fmt.Errorf("expected n to be %d, got %d", n, cap(clientRandom))
	}

	fmt.Printf("Got client random: %s\n", clientRandom)

	// read session id. this is fake data since tls 1.3.
	sessionIdLength, err := clientHelloBuf.ReadByte()
	if err != nil {
		return ParsedClientHello{}, err
	}

	fmt.Printf("Got session id length %d\n", sessionIdLength)

	sessionId := make([]byte, sessionIdLength)
	n, err = clientHelloBuf.Read(sessionId)
	if err != nil {
		return ParsedClientHello{}, err
	}

	if n != int(sessionIdLength) {
		return ParsedClientHello{}, fmt.Errorf("expected n to be %d, got %d", int(sessionIdLength), n)
	}

	fmt.Printf("Got session id %x\n", sessionId)

	var cipherSuites uint16
	err = binary.Read(clientHelloBuf, binary.BigEndian, &cipherSuites)
	if err != nil {
		return ParsedClientHello{}, err
	}

	parsedClientHello.CipherSuites = make([]uint16, 0, cipherSuites/2)
	for i := 0; i < int(cipherSuites/2); i++ {
		var cipherSuite uint16
		_ = binary.Read(clientHelloBuf, binary.BigEndian, &cipherSuite)

		parsedClientHello.CipherSuites = append(parsedClientHello.CipherSuites, cipherSuite)
	}

	compressionMethod, err := clientHelloBuf.ReadByte()
	if err != nil {
		return ParsedClientHello{}, err
	}

	compressionType, err := clientHelloBuf.ReadByte()
	if err != nil {
		return ParsedClientHello{}, err
	}

	fmt.Println("got compression method", compressionMethod)
	fmt.Println("got compression type", compressionType)

	parsedClientHello.Compression.Method = compressionMethod
	parsedClientHello.Compression.Type = compressionType

	var extensionsLength uint16
	err = binary.Read(clientHelloBuf, binary.BigEndian, &extensionsLength)
	if err != nil {
		return ParsedClientHello{}, err
	}

	if int(extensionsLength) == 0 {
		return ParsedClientHello{}, errors.New("no extensions")
	}

	fmt.Println("got extensions length", extensionsLength)

	extensionsData := make([]byte, extensionsLength)
	_, err = clientHelloBuf.Read(extensionsData)
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("unable to get extensions: %s", err.Error())
	}

	fmt.Printf("got extensions data %x\n", extensionsData)

	extensionsBuf := bytes.NewBuffer(extensionsData)

	// Each extension will start with two bytes that indicate which extension it is, followed by a two-byte
	// content length field, followed by the contents of the extension.

	for extensionsBuf.Len() > 0 {
		// extensionType (e.g. 0x00 0x00 for server name or SNI)
		var extensionType uint16

		// extensionContentLength (e.g. 0x00 0x18 (24 bytes) for extension content length
		var extensionContentLength uint16

		err = binary.Read(extensionsBuf, binary.BigEndian, &extensionType)
		if err != nil {
			return ParsedClientHello{}, err
		}

		if extensionType&greaseBitmask != 0x0A0A {
			parsedClientHello.Extensions = append(parsedClientHello.Extensions, extensionType)
		}

		err = binary.Read(extensionsBuf, binary.BigEndian, &extensionContentLength)
		if err != nil {
			return ParsedClientHello{}, err
		}

		contents := make([]byte, extensionContentLength)
		_, err = extensionsBuf.Read(contents)
		if err != nil {
			return ParsedClientHello{}, err
		}

		switch extensionType {
		case sniExtensionType:
			//00 16 - 0x16 (22) bytes of first (and only) list entry follows
			//00 - list entry is type 0x00 "DNS hostname"
			//00 13 - 0x13 (19) bytes of hostname follows
			//65 78 61 ... 6e 65 74 - "example.ulfheim.net"
			if contents[3] != 0x00 {
				return ParsedClientHello{}, errors.New("expected DNS hostname type for SNI extension")
			}

			parsedClientHello.SNI = contents[5:]

			break

		case supportedGroupsType:
			supportedGroupsListLength := uint16(contents[0])<<8 | uint16(contents[1])
			curves := int(supportedGroupsListLength) / 2
			supportedCurves := contents[2:]

			parsedClientHello.EllipticCurves = make([]uint16, 0, curves)
			for i := 0; i < curves; i++ {
				ecType := uint16(supportedCurves[i*2])<<8 | uint16(supportedCurves[1+(i*2)])
				if ecType&greaseBitmask != 0x0A0A {
					parsedClientHello.EllipticCurves = append(parsedClientHello.EllipticCurves, ecType)
				}
			}

			break
		case ecpfExtensionType:
			// we need to know which ECC compression formats are available. ECC uses an x and y plane and compression
			// for encryption and compressing this data makes the message smaller. we'll use a curl example to
			// demonstrate how this extension works: 00 0b 00 02 01 00
			// 1. 00 0b is the 'header' of this extension type. just see it as the identifier. it's already defined in
			//    extensionType.
			// 2. 00 02 - we have two bytes (with other words two compression formats) available.
			// 3. 01 - "ansiX962_compressed_prime"
			// 4. 00 - "uncompressed"
			if len(contents) < 2 {
				return ParsedClientHello{}, errors.New("unable to parse ecpfExtensionType due to invalid data")
			}

			compressionLength := contents[0]
			compressions := contents[1:]
			for i := 0; i < int(compressionLength); i++ {
				parsedClientHello.EllipticCurveCompressionFormat = append(parsedClientHello.EllipticCurveCompressionFormat, compressions[i])
			}

			break
		}
	}

	return
}
