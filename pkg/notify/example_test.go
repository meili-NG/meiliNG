package notify_test

import (
	"context"
	"fmt"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/notify"
)

// smsProvider is what a distribution adds to enable phone verification: a
// provider that sends the code to n.Recipient, an E.164 number, by SMS.
type smsProvider struct{}

func (smsProvider) Name() string { return "sms" }

func (smsProvider) Supports(key notify.NotifyKey) bool {
	return key == notify.NotifyKeyPhoneVerificationCode
}

func (smsProvider) Notify(ctx context.Context, cfg *config.MeilingConfig, n notify.Notification) error {
	// Call the SMS gateway here with n.Recipient, n.Args.String("code") and
	// n.Args.String("lang").
	return nil
}

// Phone verification is off until a provider handles
// NotifyKeyPhoneVerificationCode. A distribution registers one from an init
// function in its own module and maps the key to it in the configuration:
//
//	notification:
//	  keys:
//	    phone_verification_code: sms
//
// or, as an environment variable, MEILING_NOTIFICATION__KEYS=phone_verification_code:sms.
func ExampleRegister_phoneVerification() {
	notify.Register(smsProvider{})

	cfg := &config.MeilingConfig{}
	cfg.NotificationConfig.Keys = map[string]string{
		string(notify.NotifyKeyPhoneVerificationCode): "sms",
	}

	p, err := notify.ResolveProvider(cfg, notify.NotifyKeyPhoneVerificationCode)
	fmt.Println(p.Name(), err)
	// Output: sms <nil>
}
