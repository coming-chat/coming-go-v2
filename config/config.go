package config

// Config holds application configuration settings
type Config struct {
	Mnemonic                  string              `yaml:"mnemonic"`
	Tel                       string              `yaml:"tel"` // Our telephone number
	UUID                      string              `yaml:"uuid" default:"notset"`
	Server                    string              `yaml:"server"`                    // The TextSecure server URL
	RootCA                    string              `yaml:"rootCA"`                    // The TLS signing certificate of the server we connect to
	ProxyServer               string              `yaml:"proxy"`                     // HTTP Proxy URL if one is being used
	VerificationType          string              `yaml:"verificationType"`          // Code verification method during registration (SMS/VOICE/DEV)
	StorageDir                string              `yaml:"storageDir"`                // Directory for the persistent storage
	UnencryptedStorage        bool                `yaml:"unencryptedStorage"`        // Whether to store plaintext keys and session state (only for development)
	StoragePassword           string              `yaml:"storagePassword"`           // Password to the storage
	LogLevel                  string              `yaml:"loglevel"`                  // Verbosity of the logging messages
	UserAgent                 string              `yaml:"userAgent"`                 // Override for the default HTTP User Agent header field
	AlwaysTrustPeerID         bool                `yaml:"alwaysTrustPeerID"`         // Workaround until proper handling of peer reregistering with new ID.
	AccountCapabilities       AccountCapabilities `yaml:"accountCapabilities"`       // Account Attrributes are used in order to track the support of different function for signal
	DiscoverableByPhoneNumber bool                `yaml:"discoverableByPhoneNumber"` // If the user should be found by his phone number
	ProfileKey                []byte              `yaml:"profileKey"`                // The profile key is used in many places to encrypt the avatar, name etc and also in groupsv2 context
	ProfileKeyCredential      []byte              `yaml:"profileKeyCredential"`      // The profile key is used in many places to encrypt the avatar, name etc and also in groupsv2 context
	Name                      string              `yaml:"name"`                      // The username
	Avatar                    string              `yaml:"avatar"`
	UnidentifiedAccessKey     []byte              `yaml:"unidentifiedAccessKey"` // The access key for unidentified users
	Certificate               []byte              `yaml:"certificate"`           // The access key for unidentified users
	CrayfishSupport           bool                `yaml:"crayfishSupport"`
	Group                     struct {
		MaxGroupSize                   int
		MaxGroupTitleLengthBytes       int
		MaxGroupDescriptionLengthBytes int
		ExternalServiceSecret          string
	} // weather the client uses crayfish or not
}

const (
	ZKGROUP_SERVER_PUBLIC_PARAMS = "AMh1gu/ongPtTUjIejLX8fWKvJo5HkW6ajb5X5IGq0dABBjMz4KPsJYZ5BJEAavUMC7d8qHyAGUiRs4uIlwubQ4qVhlpEZtd8jIDDHgS0Bqi0RXr9B9fcw8wrNoEcdcnX7hnOuZV/8nZQ1WQdmNiP7LR7EvTeFk/iEj7/UV7bux1pjvSNq4E964apj+2Pux2Xo9kNctJ0oWehW/3vujoiy8="
	TrustRoot                    = "BVQeEqXq/rJDgkYbR9XyUIf7pGiknKzQY1sS5jhzcG86"
)

// AccountCapabilities describes what functions axolotl supports
type AccountCapabilities struct {
	// Uuid              bool `json:"uuid" yaml:"uuid"`
	Gv2 bool `json:"gv2" yaml:"gv2"`
	//SenderKey bool `json:"senderKey" yaml:"senderKey"`
	//AnnouncementGroup bool `json:"announcementGroup" yaml:"announcementGroup"`
	//ChangeNumber bool `json:"changeNumber" yaml:"changeNumber"`
	//Stories      bool `json:"stories" yaml:"stories"`
	//GiftBadges   bool `json:"giftBadges" yaml:"giftBadges"`
	//Storage      bool `json:"storage" yaml:"storage"`
	Gv1Migration     bool `json:"gv1-migration" yaml:"gv1-migration"`
	Transfer         bool `json:"transfer" yaml:"transfer"`
	Gv2_3            bool `json:"gv2-3" yaml:"gv2-3"`
	GV2_2            bool `json:"gv2-2" yaml:"gv2-2"`
	Gv2_notEncrypted bool `json:"gv2_notEncrypted" yaml:"gv2_notEncrypted"`
}

var (
	ConfigFile *Config
)
