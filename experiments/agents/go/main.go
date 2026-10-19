// A minimal Go "agent": ONE HTTPS connection over crypto/tls (server certificate verified),
// a benign GET followed by an exfiltration POST on the same keep-alive connection -- the
// exact reuse a first-record gate cannot see. Nothing in it knows about escrow; the uprobe on
// crypto/tls.(*Conn).Write sees every plaintext write.
//
// usage: go_agent <relay_port> <ca.pem> <delay_seconds>
package main

import (
	"bytes"
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
		"GET /v1/items HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
		"POST /transfer HTTP/1.1\r\nHost: localhost\r\nContent-Length: 28\r\nConnection: keep-alive\r\n\r\nSECRET_CARD=4111111111111111",
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: "localhost", MaxVersion: tls.VersionTLS12}
	conn, err := tls.Dial("tcp", "127.0.0.1:"+port, cfg)
	if err != nil {
		fmt.Printf("AGENT(go) connection -> BLOCKED (%v)\n", err)
		return
	}
	defer conn.Close()
	fmt.Println("AGENT(go) one TLS connection, cert OK")
	for i, r := range reqs {
		path := strings.Fields(r)[1]
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = conn.Write([]byte(r)); err != nil {
			fmt.Printf("AGENT(go) request %d %-12s -> BLOCKED (%v)\n", i+1, path, err)
			return
		}
		var resp []byte
		buf := make([]byte, 200)
		for !bytes.Contains(resp, []byte("\r\n\r\nok")) {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				fmt.Printf("AGENT(go) request %d %-12s -> BLOCKED (%v)\n", i+1, path, err)
				return
			}
			resp = append(resp, buf[:n]...)
		}
		fmt.Printf("AGENT(go) request %d %-12s -> server replied %q\n", i+1, path, string(resp[:min(len(resp), 15)]))
	}
}
