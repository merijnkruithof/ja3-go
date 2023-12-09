package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"sync"
)

var (
	FieldDelimiter = byte(',')
	ValueDelimiter = byte('-')
)

var (
	// packetBufferPool decreases GC pressure by re-using buffer objects.
	packetBufferPool = sync.Pool{New: func() any {
		return new(bytes.Buffer)
	}}
)

func MarshalJA3(packet ParsedClientHello) (ja3 string, err error) {
	// According to the documentation: JA3 gathers the decimal values of the bytes for the following fields in the
	// Client Hello packet; SSL Version, Accepted Ciphers, List of Extensions,	 Elliptic Curves, and Elliptic Curve
	// Formats. It then concatenates those values together in order, using a "," to delimit each field and a "-" to
	// delimit each value in each field.
	//
	// Fine, we'll take the intercepted ClientHello packet and begin marshaling it into a JA3 string.
	buf := packetBufferPool.Get().(*bytes.Buffer)
	defer packetBufferPool.Put(buf)

	buf.Reset()

	// Get the decimal value of the current TLS version
	sslVersion := int(uint16(packet.TLSVersion.Major)<<8 | uint16(packet.TLSVersion.Minor))

	buf.WriteString(strconv.Itoa(sslVersion))
	buf.WriteByte(FieldDelimiter)

	appendCipherSuites(buf, packet.CipherSuites)
	appendExtensionsList(buf, packet.Extensions)
	appendEllipticCurves(buf, packet.EllipticCurves)
	appendEllipticCurveFormats(buf, packet.EllipticCurveCompressionFormat)

	md5Sum := md5.Sum(buf.Bytes())
	hash := hex.EncodeToString(md5Sum[:])

	ja3 = hash

	return
}

func appendEllipticCurveFormats(buf *bytes.Buffer, ellipticCurveFormats []uint8) {
	if len(ellipticCurveFormats) <= 0 {
		// last value - we don't need a separator.
		return
	}

	for index, ellipticCurveFormat := range ellipticCurveFormats {
		buf.WriteString(strconv.Itoa(int(ellipticCurveFormat)))

		if index < len(ellipticCurveFormats)-1 {
			buf.WriteByte(ValueDelimiter)
		}
	}
}

func appendEllipticCurves(buf *bytes.Buffer, ellipticCurves []uint16) {
	if len(ellipticCurves) <= 0 {
		buf.WriteByte(FieldDelimiter)
		return
	}

	for index, ellipticCurve := range ellipticCurves {
		buf.WriteString(strconv.Itoa(int(ellipticCurve)))

		// check if the next value is the end
		if index >= len(ellipticCurves)-1 {
			buf.WriteByte(FieldDelimiter)
		} else {
			buf.WriteByte(ValueDelimiter)
		}
	}
}

func appendExtensionsList(buf *bytes.Buffer, extensions []uint16) {
	if len(extensions) <= 0 {
		buf.WriteByte(FieldDelimiter)
		return
	}

	for index, extension := range extensions {
		buf.WriteString(strconv.Itoa(int(extension)))

		// check if the next value is the end
		if index >= len(extensions)-1 {
			buf.WriteByte(FieldDelimiter)
		} else {
			buf.WriteByte(ValueDelimiter)
		}
	}
}

func appendCipherSuites(buf *bytes.Buffer, cipherSuites []uint16) {
	if len(cipherSuites) <= 0 {
		buf.WriteByte(FieldDelimiter)
		return
	}

	for index, cipherSuite := range cipherSuites {
		buf.WriteString(strconv.Itoa(int(cipherSuite)))

		// check if the next value is the end
		if index >= len(cipherSuites)-1 {
			buf.WriteByte(FieldDelimiter)
		} else {
			buf.WriteByte(ValueDelimiter)
		}
	}
}
