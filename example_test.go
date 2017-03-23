package recaptcha_test

import (
	"fmt"
	"log"

	"github.com/odeke-em/recaptcha"
)

func Example() {
	req := &recaptcha.Request{
		SecretKey: "aSecretKey",
		Response:  "goog-challenge",
		RemoteIP:  "192.168.1.24",
	}

	res, err := req.Verify()
	if err != nil {
		log.Fatalf("failed to verify: %v", err)
	}

	if !res.Success {
		log.Fatalf("failed to verify that code, errors: %v\n", res.ErrorCodes)
	}

	fmt.Printf("Successfully verified at: %v\n", res.ChallengeTimeStamp)
}
