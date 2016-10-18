package edgedetect

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

func defaultBrowserIsEdge() bool {
	k, err := registry.OpenKey(registry.CLASSES_ROOT, `ActivatableClasses\Package\DefaultBrowser_NOPUBLISHERID\Server\DefaultBrowserServer`, registry.QUERY_VALUE)
	if err != nil {
		log.Debugf("Error reading DefaultBrowserServer registry key: %v", err)
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
	_p, regErr := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`, registry.QUERY_VALUE)
	if regErr != nil {
		log.Errorf("Error reading UrlAssociations registry key: %v", regErr)
		return false
	}
	p, _, err := _p.GetStringValue("ProgId")
	if err != nil {
		log.Errorf("Could not read ProgId: %v", err)
		return false
	}

	_s, regErr := registry.OpenKey(registry.CLASSES_ROOT, p, registry.QUERY_VALUE)
	if regErr != nil {
		log.Errorf("Error reading program registry key: %v", regErr)
		return false
	}
	s, _, err := _s.GetStringValue("FriendlyTypeName")
	if err != nil {
		log.Errorf("Could not read FriendlyTypeName: %v", err)
		return false
	}

	return strings.Contains(s, "MicrosoftEdge")
}
