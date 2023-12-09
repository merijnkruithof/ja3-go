package main

import (
	tls "github.com/wwhtrbbtt/utls"
	"log"
	"net/http"
)

func main() {
	cert, err := tls.LoadX509KeyPair("certs/chain.pem", "certs/key.pem")
	if err != nil {
		log.Fatalf("Failed to load key pair: %s", err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
	}

	// Start a raw TCP listener
	ln, err := tls.Listen("tcp", ":443", &config)
	if err != nil {
		log.Fatalf("Failed to listen: %s", err)
	}

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %s", err)
			continue
		}

		go handleConnection(conn)
	}
}
