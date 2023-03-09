package rootCa

import (
	"crypto/x509"
	"os"

	"github.com/coming-chat/coming-go-v2/utils"

	log "github.com/sirupsen/logrus"
)

// rootPEM is the PEM formatted signing certificate of the Open Whisper Systems
// server to be used by the TLS client to verify its authenticity instead of
// relying on the system-wide set of root certificates.
var rootPEM = `
-----BEGIN CERTIFICATE-----
MIICrDCCAZQCCQDaZNMbw/+odDANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA0q
LmNvbWluZy5jaGF0MB4XDTIyMTAxNDA4MDM1NFoXDTIyMTExMzA4MDM1NFowGDEW
MBQGA1UEAwwNKi5jb21pbmcuY2hhdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKJJ30kuw9OMH8+QmXE+HxYpjTPxbrF7DIyVf9nH3PutX7BIPWB+w5+B
1/AE1aTlCMvqePVvEjZe0lEAZAosmhH2nkZVb9GfvQtljYi/RBgsGgn9oXNIsXcS
/ZYGQb9d4mqXM5JFFlshJAJyLuYbZmrqXUiRfjEsrEna4HAPrU1QXQf3ZTb5Vnoo
+39InDyVPCDmcpy7aCHwBtGCvWu2REAk0kZZfF3izrSiRnGJVn5/Tk5+Cho5yapZ
xOnjNbuEL+Lk2Cn/LjyMQ6B6LSJBo1IcThM0kmRkNgeJhBTPjkButwrGAvi/V4fd
kcwKKT48Y60w6FuS8x6otcJkwAC33M8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA
Qh9llAKUws3puw3Qqo4IeWuz9mVqespnI4qtIs0fkcBRuXxKssQCCcKUV/hOmdDM
iPdkrNb1Q5bm5B931mxZMMRRohj86AK+lUEvkUx4TfyURKW/0whE82cHpOOYglrB
e4CsE/2pa91qJfzHemmGL7wQqDWzTxMRzQOPmrTGlpfilQ3uiA4TX8d2KXCzTcG5
yk8qoK02qwk1KhXCFRQAE9JrLu1Kd3N+uEl5hf8TgQvfBhZ/AyIonLkfICr0VaTU
siTlOA+pQbyBH1sFimM+gJfW7IB2QtUXbQUZJugqVEBDNdiBRPNFM14nASyat9JJ
3WiYCZLmeCU55QErxMccSw==
-----END CERTIFICATE-----
`
var directoryPEM = `
-----BEGIN CERTIFICATE-----
MIICrDCCAZQCCQDaZNMbw/+odDANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA0q
LmNvbWluZy5jaGF0MB4XDTIyMTAxNDA4MDM1NFoXDTIyMTExMzA4MDM1NFowGDEW
MBQGA1UEAwwNKi5jb21pbmcuY2hhdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKJJ30kuw9OMH8+QmXE+HxYpjTPxbrF7DIyVf9nH3PutX7BIPWB+w5+B
1/AE1aTlCMvqePVvEjZe0lEAZAosmhH2nkZVb9GfvQtljYi/RBgsGgn9oXNIsXcS
/ZYGQb9d4mqXM5JFFlshJAJyLuYbZmrqXUiRfjEsrEna4HAPrU1QXQf3ZTb5Vnoo
+39InDyVPCDmcpy7aCHwBtGCvWu2REAk0kZZfF3izrSiRnGJVn5/Tk5+Cho5yapZ
xOnjNbuEL+Lk2Cn/LjyMQ6B6LSJBo1IcThM0kmRkNgeJhBTPjkButwrGAvi/V4fd
kcwKKT48Y60w6FuS8x6otcJkwAC33M8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA
Qh9llAKUws3puw3Qqo4IeWuz9mVqespnI4qtIs0fkcBRuXxKssQCCcKUV/hOmdDM
iPdkrNb1Q5bm5B931mxZMMRRohj86AK+lUEvkUx4TfyURKW/0whE82cHpOOYglrB
e4CsE/2pa91qJfzHemmGL7wQqDWzTxMRzQOPmrTGlpfilQ3uiA4TX8d2KXCzTcG5
yk8qoK02qwk1KhXCFRQAE9JrLu1Kd3N+uEl5hf8TgQvfBhZ/AyIonLkfICr0VaTU
siTlOA+pQbyBH1sFimM+gJfW7IB2QtUXbQUZJugqVEBDNdiBRPNFM14nASyat9JJ
3WiYCZLmeCU55QErxMccSw==
-----END CERTIFICATE-----
`
var RootCA *x509.CertPool
var DirectoryCA *x509.CertPool

func SetupCA(rootca string) {
	pem := []byte(rootPEM)
	if rootca != "" && utils.Exists(rootca) {
		b, err := os.ReadFile(rootca)
		if err != nil {
			log.Error(err)
			return
		}
		pem = b
	}

	RootCA = x509.NewCertPool()
	if !RootCA.AppendCertsFromPEM(pem) {
		log.Error("[textsecure] Cannot load PEM")
	}
	directoryPem := []byte(directoryPEM)
	DirectoryCA = x509.NewCertPool()
	if !DirectoryCA.AppendCertsFromPEM(directoryPem) {
		log.Error("[textsecure] Cannot load directory PEM")
	}

}
