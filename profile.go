package textsecure

import "github.com/coming-chat/coming-go-v2/config"

// SetUsername sets the profile name
func SetUsername(name string) {
	config.ConfigFile.Name = name
	saveConfig(config.ConfigFile)
}
