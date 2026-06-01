package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

const (
	socksVersion = 0x05

	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNoAccept = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03

	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repCommandNotSupp   = 0x07
	repAddrTypeNotSupp  = 0x08
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(client net.Conn) {
	defer client.Close()

	method, err := negotiateAuth(client)
	if err != nil {
		return
	}

	if method == methodUserPass {
		if err := authenticateUserPass(client); err != nil {
			return
		}
	}

	host, port, rep, err := readConnectRequest(client)
	if err != nil {
		sendReply(client, rep)
		return
	}

	targetAddr := fmt.Sprintf("%s:%d", host, port)
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		sendReply(client, repGeneralFailure)
		return
	}
	defer target.Close()

	if err := sendReply(client, repSuccess); err != nil {
		return
	}

	relay(client, target)
}

func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return methodNoAccept, err
	}

	if header[0] != socksVersion {
		conn.Write([]byte{socksVersion, methodNoAccept})
		return methodNoAccept, fmt.Errorf("invalid SOCKS version")
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return methodNoAccept, err
	}

	userRequired := os.Getenv("PROXY_USER") != ""

	if userRequired {
		if containsMethod(methods, methodUserPass) {
			conn.Write([]byte{socksVersion, methodUserPass})
			return methodUserPass, nil
		}
	} else {
		if containsMethod(methods, methodNoAuth) {
			conn.Write([]byte{socksVersion, methodNoAuth})
			return methodNoAuth, nil
		}
	}

	conn.Write([]byte{socksVersion, methodNoAccept})
	return methodNoAccept, fmt.Errorf("no acceptable auth method")
}

func containsMethod(methods []byte, wanted byte) bool {
	for _, method := range methods {
		if method == wanted {
			return true
		}
	}
	return false
}

func authenticateUserPass(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid auth version")
	}

	uLen := int(header[1])
	username := make([]byte, uLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return err
	}

	pLen := int(pLenBuf[0])
	password := make([]byte, pLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(username) == expectedUser && string(password) == expectedPass {
		conn.Write([]byte{0x01, 0x00})
		return nil
	}

	conn.Write([]byte{0x01, 0x01})
	return fmt.Errorf("invalid username or password")
}

func readConnectRequest(conn net.Conn) (string, uint16, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, repGeneralFailure, err
	}

	if header[0] != socksVersion {
		return "", 0, repGeneralFailure, fmt.Errorf("invalid SOCKS version")
	}

	if header[1] != cmdConnect {
		return "", 0, repCommandNotSupp, fmt.Errorf("command not supported")
	}

	if header[2] != 0x00 {
		return "", 0, repGeneralFailure, fmt.Errorf("invalid reserved byte")
	}

	atyp := header[3]
	var host string

	switch atyp {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, repGeneralFailure, err
		}
		host = net.IP(addr).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, repGeneralFailure, err
		}

		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, repGeneralFailure, err
		}
		host = string(domain)

	default:
		return "", 0, repAddrTypeNotSupp, fmt.Errorf("address type not supported")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, repGeneralFailure, err
	}

	port := binary.BigEndian.Uint16(portBuf)
	return host, port, repSuccess, nil
}

func sendReply(conn net.Conn, rep byte) error {
	reply := []byte{
		socksVersion,
		rep,
		0x00,
		atypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	_, err := conn.Write(reply)
	return err
}

func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)
		closeWrite(target)
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)
		closeWrite(client)
	}()

	wg.Wait()
}

func closeWrite(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
	}
}