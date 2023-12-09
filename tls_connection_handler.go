package main

import (
	"fmt"
	"github.com/valyala/fasthttp"
	tls "github.com/wwhtrbbtt/utls"
	"log"
	"net"
)

func handleConnection(c net.Conn) {
	// we'll need an instance of *tls.Conn in order to start the TLS handshake.
	conn, ok := c.(*tls.Conn)
	if !ok {
		log.Println("conn is not an instance of *tls.Conn (utls lib)")

		// close the connection manually before returning
		if err := c.Close(); err != nil {
			log.Println("handle conn: unable to close connection: ", err.Error())
		}
		return
	}

	if err := conn.Handshake(); err != nil {
		// we do not serve requests without TLS, so exit method.
		log.Println("handleConn: unable to handshake TLS connection. Underlying error:", err.Error())

		// close the connection manually before returning
		if err := c.Close(); err != nil {
			log.Println("handle conn: unable to close connection: ", err.Error())
		}

		return
	}

	clientHello, err := ParseClientHello(conn.ClientHello)
	if err != nil {
		log.Println("unable to parse client hello", err)
		return
	}

	ja3Hash, err := MarshalJA3(clientHello)
	if err != nil {
		log.Println("unable to get ja3", err.Error())
		return
	}

	// dump the ja3 hash in the terminal instead of the browser, just to avoid writing code.
	fmt.Println("Got JA3 hash", ja3Hash)

	// fasthttp.ServeConn is now responsible for closing c when it's done.
	if err := fasthttp.ServeConn(c, HandleRequest); err != nil {
		log.Println("handleConn: unable to serve request. Underlying error:", err.Error())
	}
}
