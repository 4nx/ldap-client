package ldap

import (
	"crypto/tls"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"gopkg.in/ldap.v3"
)

// validate instance of go-playground validator v10
var validate *validator.Validate

// LdapConfig will hold the config which are needed to connect and search
type LdapConfig struct {
	Conn         *ldap.Conn
	Host         string `validate:"required,ipv4|ipv6|hostname|fqdn"`
	Port         int    `validate:"required,number,gt=0,let=65535"`
	BindUser     string `validate:"required,printascii,excludesall=!?*%&/\()[]{}$#<>.,"`
	BindPassword string `validate:"required,printascii,max=50"`
	BaseDN       string `validate:"required,printascii,excludesall=!?*%&/\()[]{}$#<>.,"`
	ServerName   string `validate:"required,ipv4|ipv6|hostname|fqdn"`
	Attributes   string `validate:"required,printascii,excludesall=!?*%&/\()[]{}$#<>."`
}

func (lc *LdapConfig) init() error {
	validate = validator.New()

	err := validate.Struct(lc)

	for _, e := range err.(validator.ValidationErrors) {
		log.Printf("Input validation failed: %s", e)
	}

	return err
}

// Close will close the LDAP connection
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

// Authenticate will bind, search for a user and authenticate
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
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", username),
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
		}

		log.Printf("Too many results: %d", len(s.Entries))
		return nil, fmt.Errorf("Too many results: %d", len(s.Entries))
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

// CheckGroupMembership will check if a given user is member of a given group
func (lc *LdapConfig) CheckGroupMembership(username, group string) (bool, error) {
	re := regexp.MustCompile("CN=([a-zA-Z0-9_-]+?),")

	err := lc.ldapsConnect()
	if err != nil {
		return false, err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=group)(cn=%s))", group),
		[]string{"member"},
		nil,
	)

	s, err := lc.Conn.Search(searchRequest)
	if err != nil {
		log.Printf("Group search failed: %v", err)
		return false, err
	}

	memberDN := s.Entries[0].GetAttributeValue("member")
	member := re.FindStringSubmatch(memberDN)
	if strings.ToLower(username) != strings.ToLower(member[1]) {
		return false, fmt.Errorf("User %s is not member of group: %s", username, group)
	}

	return true, nil
}
