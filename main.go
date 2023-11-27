package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/9072997/fingerprintverifier"
	"github.com/kardianos/service"
	"golang.org/x/crypto/ssh"
)

type Connection struct {
	Name              string
	Host              string
	Username          string
	KeyFile           string
	Key               string
	Password          string
	Fingerprint       string
	KeepAliveInterval Duration
	MaxReconnectDelay Duration
	Tunnels           []*Tunnel

	// internal fields
	status         atomic.Value
	auth           ssh.AuthMethod
	conn           *ssh.Client
	listeners      []net.Listener
	reconnectDelay time.Duration
}

type Tunnel struct {
	From Endpoint
	To   Endpoint

	// internal fields
	direction TunnelDirection
}

type Endpoint struct {
	Side    string
	Address string
}

type TunnelDirection int

const (
	UnspecifiedDirection TunnelDirection = iota
	ExposedOnServer
	ExposedLocally
)

type program struct {
	Config []*Connection
}

func main() {
	s, _ := service.New(
		new(program),
		&service.Config{
			Name:        "TunTun",
			DisplayName: "TunTun",
			Description: "Maintains persistent SSH tunnels.",
		},
	)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			err := s.Install()
			if err != nil {
				panic(err)
			}
			return
		case "uninstall":
			err := s.Uninstall()
			if err != nil {
				panic(err)
			}
			return
		}
	}

	err := s.Run()
	if err != nil {
		panic(err)
	}
}

func (p *program) Start(s service.Service) error {
	// read config file
	path := GetConfigPath()
	j, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	err = json.Unmarshal(j, &p.Config)
	if err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// validate config
	if len(p.Config) == 0 {
		return fmt.Errorf("no connections defined in config")
	}
	for _, c := range p.Config {
		issue := c.validate()
		if issue != "" {
			return fmt.Errorf("invalid config: %s", issue)
		}
	}

	// connect to SSH servers
	for _, c := range p.Config {
		go Handle(c)
	}

	return nil
}

func (p *program) Stop(s service.Service) error {
	// let the os figure it out
	return nil
}

func (c *Connection) setStatus(status string) {
	log.Println(c.Name + ": " + status)
	c.status.Store(status)
}

func (c *Connection) getStatus() string {
	s := c.status.Load()
	if s == nil {
		return ""
	}
	return s.(string)
}

func (c *Connection) validate() string {
	if c.Name == "" {
		return "connection has no name"
	}
	if c.Host == "" {
		return "host is empty for connection " + c.Name
	}
	if c.Username == "" {
		return "username is empty for connection " + c.Name
	}
	if len(c.Tunnels) == 0 {
		return "no tunnels defined for connection " + c.Name
	}
	if c.KeepAliveInterval.Unwrap() == 0 {
		c.KeepAliveInterval.Set(time.Minute)
	}
	if c.MaxReconnectDelay.Unwrap() == 0 {
		c.MaxReconnectDelay.Set(time.Minute)
	}

	// KeyFile and Key are mutually exclusive
	if c.KeyFile != "" && c.Key != "" {
		return "connection " + c.Name + " has both KeyFile and Key set"
	}

	// check that Host resolves
	host, _, err := net.SplitHostPort(c.Host)
	if err != nil {
		// default to port 22
		host = c.Host
		c.Host = net.JoinHostPort(c.Host, "22")
	}
	addrs, _ := net.LookupHost(host)
	if len(addrs) == 0 {
		return "failed to resolve host " + c.Host + " for connection " + c.Name
	}

	// try to read key (if set)
	var key []byte
	if c.KeyFile != "" {
		var err error
		key, err = os.ReadFile(c.KeyFile)
		if err != nil {
			return "failed to read key file " + c.KeyFile + " for connection " + c.Name + ": " + err.Error()
		}
	} else if c.Key != "" {
		key = []byte(c.Key)
	}

	// try to parse key
	if key != nil {
		// is there a password for the key?
		var signer ssh.Signer
		var err error
		if c.Password == "" {
			signer, err = ssh.ParsePrivateKey(key)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(c.Password))
		}
		if err != nil {
			return "failed to parse key for connection " + c.Name + ": " + err.Error()
		}
		c.auth = ssh.PublicKeys(signer)
	}

	// if no key is set, try to use password
	if c.auth == nil && c.Password != "" {
		c.auth = ssh.Password(c.Password)
	}

	// check tunnels
	for _, t := range c.Tunnels {
		if t.From.Side == "" {
			return c.Name + ".From.Side is empty"
		}
		if t.From.Address == "" {
			return c.Name + ".From.Address is empty"
		}
		if t.To.Side == "" {
			return c.Name + ".To.Side is empty"
		}
		if t.To.Address == "" {
			return c.Name + ".To.Address is empty"
		}

		// tunnel must have a Local and Remote endpoint
		if t.From.Side == "Local" && t.To.Side == "Remote" {
			t.direction = ExposedLocally
		} else if t.From.Side == "Remote" && t.To.Side == "Local" {
			t.direction = ExposedOnServer
		} else {
			return "for connection " + c.Name + ", tunnel should be Local->Remote or Remote->Local"
		}

		// check that From and To are valid
		_, fromPort, err := net.SplitHostPort(t.From.Address)
		if err != nil {
			return "for connection " + c.Name + ", tunnel From address is invalid: " + err.Error()
		}
		if fromPort == "" {
			return "for connection " + c.Name + ", tunnel From address is missing port number"
		}
		_, toPort, err := net.SplitHostPort(t.To.Address)
		if err != nil {
			return "for connection " + c.Name + ", tunnel To address is invalid: " + err.Error()
		}
		if toPort == "" {
			return "for connection " + c.Name + ", tunnel To address is missing port number"
		}
	}

	return ""
}

func (c *Connection) connect() bool {
	if c.conn != nil {
		c.setStatus("already connected")
		return true
	}

	issue := c.validate()
	if issue != "" {
		c.setStatus(issue)
		return false
	}

	// connect to SSH server
	c.setStatus("connecting")
	var authMethods []ssh.AuthMethod
	if c.auth != nil {
		authMethods = []ssh.AuthMethod{c.auth}
	}
	var err error
	c.conn, err = ssh.Dial("tcp", c.Host, &ssh.ClientConfig{
		User:            c.Username,
		Auth:            authMethods,
		HostKeyCallback: fingerprintverifier.New(c.Fingerprint),
	})
	if err != nil {
		c.setStatus("failed to connect to " + c.Host + ": " + err.Error())
		return false
	}

	// establish tunnels
	c.setStatus("configuring tunnels")
	for _, t := range c.Tunnels {
		switch t.direction {
		case ExposedLocally:
			l, err := net.Listen("tcp", t.From.Address)
			if err != nil {
				c.setStatus("failed to listen on " + t.From.Address + " (Local): " + err.Error())
				continue
			}
			c.listeners = append(c.listeners, l)
			go Forward(l, t.To.Address, c.conn.Dial, c.setStatus)
		case ExposedOnServer:
			r, err := c.conn.Listen("tcp", t.From.Address)
			if err != nil {
				c.setStatus("failed to listen on " + t.From.Address + " (Remote): " + err.Error())
				continue
			}
			c.listeners = append(c.listeners, r)
			go Forward(r, t.To.Address, net.Dial, c.setStatus)
		default:
			panic("invalid tunnel direction")
		}
	}
	c.setStatus("ok")

	return true
}

func (c *Connection) Close() error {
	if c.conn != nil {
		go c.conn.Close()
	}
	c.conn = nil
	for _, l := range c.listeners {
		go l.Close()
	}
	c.listeners = nil
	return nil
}

func (c *Connection) IsAlive(timeout time.Duration) bool {
	if c.conn == nil {
		return false
	}

	t := time.NewTimer(timeout)
	defer t.Stop()

	errChan := make(chan error)
	go func() {
		_, _, err := c.conn.SendRequest("keepalive@openssh.com", true, nil)
		errChan <- err
	}()

	select {
	case <-t.C:
		return false
	case err := <-errChan:
		return err == nil
	}
}

func Handle(c *Connection) {
	kii := c.KeepAliveInterval.Unwrap()
	t := time.NewTicker(kii)
	defer t.Stop()
	c.reconnectDelay = time.Second

	for {
		if c.IsAlive(kii / 10 * 9) {
			c.reconnectDelay = time.Second
			<-t.C
			continue
		}
		c.setStatus("disconnected")

		// reconnect
		c.Close()
		success := c.connect()

		if !success {
			// exponential backoff
			c.reconnectDelay *= 2
			if c.reconnectDelay > c.MaxReconnectDelay.Unwrap() {
				c.reconnectDelay = c.MaxReconnectDelay.Unwrap()
			}
			c.setStatus("reconnecting in " + c.reconnectDelay.String())
			time.Sleep(c.reconnectDelay)
		}
	}
}
