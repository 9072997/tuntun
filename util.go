package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type Pipe struct {
	conn1  net.Conn
	conn2  net.Conn
	close1 sync.Once
	close2 sync.Once
}

func ConnectConns(conn1, conn2 net.Conn) *Pipe {
	log.Printf(
		"Connecting %s <-> %s",
		conn1.RemoteAddr().String(),
		conn2.RemoteAddr().String(),
	)
	p := &Pipe{conn1: conn1, conn2: conn2}
	go func() {
		io.Copy(conn2, conn1)
		p.Close()
	}()
	go func() {
		io.Copy(conn1, conn2)
		p.Close()
	}()
	return p
}

func (p *Pipe) Close() error {
	var err1, err2 error
	p.close1.Do(func() {
		err1 = p.conn1.Close()
	})
	p.close2.Do(func() {
		err2 = p.conn2.Close()
	})
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return nil
}

type DialFunc func(network, addr string) (net.Conn, error)
type LogFunc func(string)

func Forward(from net.Listener, to string, with DialFunc, log LogFunc) {
	for {
		conn, err := from.Accept()
		if err != nil {
			log("error listening on " + from.Addr().String() + ": " + err.Error())
			return
		}
		go func() {
			toConn, err := with("tcp", to)
			if err != nil {
				conn.Close()
				log("failed to connect to " + to + ": " + err.Error())
				return
			}
			ConnectConns(conn, toConn)
		}()
	}
}

func GetConfigPath() string {
	configPath := os.Getenv("TUNTUN_CONFIG")
	if configPath != "" {
		return configPath
	}

	switch runtime.GOOS {
	case "windows":
		configPath = filepath.Join(
			os.Getenv("PROGRAMDATA"),
			"TunTun",
			"config.json",
		)
	case "darwin":
		configPath = "/Library/Preferences/TunTun/config.json"
	default: // Unix like
		configPath = "/etc/tuntun/config.json"
	}

	// make directory if it doesn't exist
	dir := filepath.Dir(configPath)
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		os.MkdirAll(dir, 0700)
	}

	// write sample config if it doesn't exist
	_, err = os.Stat(configPath)
	if os.IsNotExist(err) {
		j, _ := json.MarshalIndent(sampleConfig, "", "\t")
		err := os.WriteFile(configPath+".example", j, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write sample config: "+err.Error())
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "Config file not found. A sample config has been written to "+configPath+".example")
		os.Exit(1)
	}

	return configPath
}

var sampleSSHKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAt7ySSyV24SrlN799YcIQYwnZmB3uIHgnPS5wF/akHdiWZprD+Z1U
5sc8S6xxCzW1TIHVeexEUaZv9AbZu+FkqL80ThNW/RutI1bMsaqQXouCynr3oQfvZW8Ckf
vtKGJ9dpRABLaF6VrpOnMd0RgzAApE0l7LvrFXVLG5JVRi2DMAAAIAf9cYoH/XGKAAAAAH
c3NoLXJzYQAAAIEAt7ySSyV24SrlN799YcIQYwnZmB3uIHgnPS5wF/akHdiWZprD+Z1U5s
c8S6xxCzW1TIHVeexEUaZv9AbZu+FkqL80ThNW/RutI1bMsaqQXouCynr3oQfvZW8Ckfvt
KGJ9dpRABLaF6VrpOnMd0RgzAApE0l7LvrFXVLG5JVRi2DMAAAADAQABAAAAgD59CsA1+K
1x2k1QegMSbmJQikma/E7crnO3ZHYx8vUXoWc6AabWZHaskgwmlLe8R3HCwmjZ+w5N7ctv
vQOSD5pkF+hQ3x/FePhi6qiAVJNCEag/J54NJDZj9cquQqTtXcygj2kQ8BKQGI98/gIJv4
/otT4kQ+aGekTRjjHPosh5AAAAQGj6Iertn8jRfgpFGaOQQ4/AyMlQIHfCc2pXOLeaeLXJ
ppJEMAh74yvco4yzTHVlZuZO1CVWpOt1wsEVm7cRZTMAAABBAPMqOrP1l0pidHRu8V5i2s
GMKDlNMf4OhpmKdgBHxVJScHW3Zb55V9FGsam2E5LgaxrjykMMTaaNBN1v6ql4ficAAABB
AMFvUMbKbNQNHG8hvwXW/OVeZsxdtVUg1qd6rLj1I9jPqCzj3a/rLKifDxpoG4VTwdoJiX
atjLHiLN6Tr3Q56RUAAAAGbm9uYW1lAQIDBAU=
-----END OPENSSH PRIVATE KEY-----`

var sampleConfig = []Connection{
	{
		Name:              "My Database Server",
		Host:              "db.example.com:22",
		Username:          "root",
		Password:          "P@ssw0rd",
		Fingerprint:       "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
		KeepAliveInterval: Duration{30 * time.Second},
		MaxReconnectDelay: Duration{5 * time.Minute},
		Tunnels: []*Tunnel{
			{
				From: Endpoint{
					Side:    "Local",
					Address: "127.0.0.1:30000",
				},
				To: Endpoint{
					Side:    "Remote",
					Address: "127.0.0.1.3306",
				},
			},
		},
	}, {
		Name:        "A Server With A Public IP",
		Host:        "example.com:22",
		Username:    "root",
		KeyFile:     "/path/to/key.pem",
		Password:    "MyKeyFilePassword",
		Fingerprint: "MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48",
		Tunnels: []*Tunnel{
			{
				From: Endpoint{
					Side:    "Remote",
					Address: "0.0.0.0:80",
				},
				To: Endpoint{
					Side:    "Local",
					Address: "127.0.0.1:80",
				},
			},
		},
	}, {
		Name:     "Something I Want To Expose To My LOCAL Network",
		Host:     "gateway-server.example.com:22",
		Username: "root",
		Key:      sampleSSHKey,
		Tunnels: []*Tunnel{
			{
				From: Endpoint{
					Side:    "Local",
					Address: "0.0.0.0:515",
				},
				To: Endpoint{
					Side:    "Remote",
					Address: "printer.example.com:515",
				},
			},
		},
	},
}
