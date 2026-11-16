package common

import (
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/nyaruka/phonenumbers"
)

func GeneralizePhone(cfg *config.MeilingConfig, phone string) (string, error) {
	num, err := phonenumbers.Parse(phone, cfg.AuthConfig.Phone.FallbackCountry)
	if err != nil {
		return "", err
	}

	return phonenumbers.Format(num, phonenumbers.E164), nil
}
