package ldap

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"

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
	Attributes   string
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
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			},
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

func (lc *LdapConfig) Authenticate(username, password string) (map[string]string, error) {
	attr := strings.Split(lc.Attributes, ",")

	err := lc.ldapsConnect()
	if err != nil {
		return nil, err
	}

	err = lc.Conn.Bind(lc.BindUser, lc.BindPassword)
	if err != nil {
		log.Printf("Failed to bind: %v", err)
		return nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&"+lc.UserSearch+")", username),
		append(attr, "dn"),
		nil,
	)

	s, err := lc.Conn.Search(searchRequest)
	if err != nil {
		log.Printf("User search failed: %v", err)
		return nil, err
	}

	if len(s.Entries) != 1 {
		if len(s.Entries) == 0 {
			log.Printf("User not found: %s", username)
			return nil, fmt.Errorf("User not found: %s", username)
		} else {
			log.Printf("Too many results: %d", len(s.Entries))
			return nil, fmt.Errorf("Too many results: %d", len(s.Entries))
		}
	}

	userAttr := map[string]string{}
	for _, attribute := range attr {
		userAttr[attribute] = s.Entries[0].GetAttributeValue(attribute)
	}

	err = lc.Conn.Bind(s.Entries[0].DN, password)
	if err != nil {
		log.Printf("Failed to authenticate user: %v", err)
		return nil, fmt.Errorf("Failed to authenticate user: %v", err)
	}
	return userAttr, nil
}
