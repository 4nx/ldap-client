package ldap

import (
	"crypto/tls"
	"fmt"
	"log"

	"gopkg.in/ldap.v3"
)

// LdapConfig will hold the config which are needed to connect and search
type LdapConfig struct {
	Conn         *ldap.Conn
	Host         string
	Port         int
	BindUser     string
	BindPassword string
	BaseDN       string
	ServerName   string
	UserSearch   string // e.g. (objectclass=user)(sAMAccount=%s)
}

func (lc *LdapConfig) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

func (lc *LdapConfig) ldapsConnect() error {
	if lc.Conn == nil {
		var l *ldap.Conn
		serverAddress := fmt.Sprintf("%s:%d", lc.Host, lc.Port)

		tlsConfig := tls.Config{
			// TODO: add root ca to this
			InsecureSkipVerify: true,
			ServerName:         lc.ServerName,
			// TODO: set CipherSuites
			//CipherSuites: []uint16{
			//	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			//	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			//	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			//},
			MinVersion: tls.VersionTLS12,
		}

		l, err := ldap.DialTLS("tcp", serverAddress, &tlsConfig)
		if err != nil {
			return err
		}
		lc.Conn = l
	}
	return nil
}

func (lc *LdapConfig) Authenticate(username, password string) (string, error) {
	err := lc.ldapsConnect()
	if err != nil {
		return "", err
	}

	err = lc.Conn.Bind(lc.BindUser, lc.BindPassword)
	if err != nil {
		log.Printf("Failed to bind: %v", err)
		return "", err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&"+lc.UserSearch+")", username),
		[]string{"dn"},
		nil,
	)

	s, err := lc.Conn.Search(searchRequest)
	if err != nil {
		log.Printf("User search failed: %v", err)
		return "", err
	}

	if len(s.Entries) != 1 {
		if len(s.Entries) == 0 {
			log.Printf("User not found: %s", username)
			return "", fmt.Errorf("User not found: %s", username)
		} else {
			log.Printf("Too many results: %d", len(s.Entries))
			return "", fmt.Errorf("Too many results: %d", len(s.Entries))
		}
	}

	userDn := s.Entries[0].DN

	err = lc.Conn.Bind(userDn, password)
	if err != nil {
		log.Printf("Failed to authenticate user: %v", err)
	}
	return userDn, nil
}
