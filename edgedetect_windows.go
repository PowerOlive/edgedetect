package edgedetect

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

func defaultBrowserIsEdge() bool {
	k, err := registry.OpenKey(registry.CLASSES_ROOT, `ActivatableClasses\Package\DefaultBrowser_NOPUBLISHERID\Server\DefaultBrowserServer`, registry.QUERY_VALUE)
	if err != nil {
		log.Errorf("Error reading DefaultBrowserServer registry key: %v", err)
		return checkURLAssociations()
	}
	defer k.Close()

	s, _, err := k.GetStringValue("AppUserModelId")
	if err != nil {
		log.Tracef("Error reading AppUserModelId: %v", err)
		return checkURLAssociations()
	}

	log.Tracef("AppUserModelId: %v", s)
	return strings.Contains(s, "MicrosoftEdge")
}

func checkURLAssociations() bool {
	k, regErr := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`, registry.QUERY_VALUE)
	if regErr != nil {
		log.Errorf("Error reading UrlAssociations registry key: %v", regErr)
		return false
	}
	s, _, err := k.GetStringValue("ProgId")
	if err != nil {
		log.Errorf("Could not read ProgId: %v", err)
		return false
	}

	// This is an Edge programming ID, but it's not clear it's constant.
	return s == "AppXq0fevzme2pys62n3e0fbqa7peapykr8v"
}
