# ja3-go
This is my own implementation of the TLS fingerprint method JA3. 

Many JA3 implementations in Go expect things such as reading a network file or doing some (quasi) low-level stuff such as
HTTP/1.x or HTTP/2 parsing. This package isn't doing that - it's taking advantage of fasthttp's `ServeConn` to serve the
connection with the underlying `net.Conn` instance of the `utls` package.

I learned tons about TLS (in particular the ClientHello packet) and fingerprinting. That's the main motivation of this 
repository. It won't be maintained.

### Requirements
1. Go 1.21
2. OpenSSL or another tool to generate a self-signed certificate for testing purposes

### Trying it out
You'll need at least a self-signed certificate to test it out. Generate one in the terminal:
```shell
openssl req -x509 -newkey rsa:2046 -keyout certs/key.pem -out certs/chain.pem -sha256 -days 365 -nodes
```

Run `go run .` in the root directory and the webserver will start.

### License
There's no license. Do whatever you want with it.