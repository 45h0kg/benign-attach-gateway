// A minimal Go "agent": makes two HTTPS requests over crypto/tls, verifying the server
// certificate, exactly like the Python client in tls_gate_demo.py. Nothing in it knows
// about escrow; the uprobe on crypto/tls.(*Conn).Write sees its plaintext.
//
// usage: go_agent <relay_port> <ca.pem> <delay_seconds>
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	port := os.Args[1]
	ca, _ := os.ReadFile(os.Args[2])
	delay, _ := strconv.ParseFloat(os.Args[3], 64)
	time.Sleep(time.Duration(delay * float64(time.Second)))

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	reqs := []string{
		"GET /v1/items HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
		"POST /transfer HTTP/1.1\r\nHost: localhost\r\nContent-Length: 28\r\nConnection: close\r\n\r\nSECRET_CARD=4111111111111111",
	}
	for _, r := range reqs {
		path := strings.Fields(r)[1]
		cfg := &tls.Config{RootCAs: pool, ServerName: "localhost", MaxVersion: tls.VersionTLS12}
		conn, err := tls.Dial("tcp", "127.0.0.1:"+port, cfg)
		if err != nil {
			fmt.Printf("AGENT(go) request %-16s -> BLOCKED (%v)\n", path, err)
			time.Sleep(1500 * time.Millisecond)
			continue
		}
		if _, err = conn.Write([]byte(r)); err != nil {
			fmt.Printf("AGENT(go) request %-16s -> BLOCKED (%v)\n", path, err)
			conn.Close()
			time.Sleep(1500 * time.Millisecond)
			continue
		}
		buf := make([]byte, 200)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			fmt.Printf("AGENT(go) request %-16s -> BLOCKED (%v)\n", path, err)
		} else {
			fmt.Printf("AGENT(go) request %-16s -> cert OK, server replied %q\n", path, string(buf[:min(n, 15)]))
		}
		conn.Close()
		time.Sleep(1500 * time.Millisecond)
	}
}
