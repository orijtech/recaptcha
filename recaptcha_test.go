package recaptcha_test

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/odeke-em/go-uuid"
	"github.com/odeke-em/recaptcha"
)

func TestFullRoundTrip(t *testing.T) {
	// Generate unique keys on every run to mimick
	// Google's typical backend.
	transport := &customBackend{
		secretKey:         uuid.NewRandom().String(),
		challengeResponse: uuid.NewRandom().String(),
	}

	tests := [...]struct {
		req           *recaptcha.Request
		wantResErrors []string
		mustErr       bool
	}{
		0: {
			req:     &recaptcha.Request{},
			mustErr: true,
			wantResErrors: []string{
				"missing input-secret",
				"missing input-response",
			},
		},
		1: {
			mustErr: true,
			req: &recaptcha.Request{
				SecretKey: "aKey",
			},
			wantResErrors: []string{
				"missing input-response",
			},
		},

		2: {
			req: &recaptcha.Request{
				SecretKey: "aKey",
				Response:  "aResponse",
			},
			wantResErrors: []string{
				"invalid-input-response",
				"invalid-input-secret",
			},
		},

		// Successful verification request
		3: {
			req: &recaptcha.Request{
				SecretKey: transport.secretKey,
				Response:  transport.challengeResponse,
			},
		},
	}

	for i, tt := range tests {
		if tt.req != nil {
			tt.req.Transport = transport
		}

		res, err := tt.req.Verify()
		if tt.mustErr {
			if err == nil {
				t.Errorf("#%d: want error", i)
			}
			if res != nil {
				t.Errorf("#%d: unexpectedly gave back a response", i)
			}
			continue
		}

		if err != nil {
			t.Errorf("#%d: err=%q", i, err)
			continue
		}

		mustSucceed := len(tt.wantResErrors) < 1
		if mustSucceed {
			if res == nil {
				t.Errorf("#%d: expected a non-nil response", i)
			} else if !res.Success {
				t.Errorf("#%d: was expected to succeed, got : %#v", i, res)
			}
			continue
		}

		got, want := res.ErrorCodes, tt.wantResErrors[:]
		// Sort them and compare
		sort.Strings(got)
		sort.Strings(want)

		if !reflect.DeepEqual(got, want) {
			t.Errorf("#%d\ngot= %#v\nwant=%#v", i, got, want)
		}
	}
}

type customBackend struct {
	sync.RWMutex
	secretKey         string
	challengeResponse string
}

var _ http.RoundTripper = (*customBackend)(nil)

func (cb *customBackend) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != "POST" {
		res := makeCodedResponse(http.StatusMethodNotAllowed, []byte("only accepts POST"))
		return res, nil
	}

	var errsList []string
	secretKey := req.PostFormValue("secret")
	if secretKey == "" {
		errsList = append(errsList, "missing-input-secret")
	}
	response := req.PostFormValue("response")
	if response == "" {
		errsList = append(errsList, "missing-input-response")
	}

	cb.RLock()
	wantSecretKey, wantChallengeResponse := cb.secretKey, cb.challengeResponse
	cb.RUnlock()

	if response != wantChallengeResponse {
		errsList = append(errsList, "invalid-input-response")
	}
	if secretKey != wantSecretKey {
		errsList = append(errsList, "invalid-input-secret")
	}

	verifyRes := new(recaptcha.Response)
	if len(errsList) < 1 {
		verifyRes.Success = true
		now := time.Now()
		verifyRes.ChallengeTimeStamp = &now
	} else {
		verifyRes.ErrorCodes = errsList
	}

	blob, err := json.Marshal(verifyRes)
	if err != nil {
		res := makeCodedResponse(http.StatusInternalServerError, []byte(err.Error()))
		return res, err
	}

	res := makeCodedResponse(http.StatusOK, blob)
	res.Status = "200 OK"
	res.Header = make(http.Header)
	res.Header.Set("Content-Type", "application/json")

	return res, nil
}

func makeCodedResponse(code int, body []byte) *http.Response {
	res := &http.Response{
		StatusCode: code,
	}
	if len(body) > 0 {
		prc, pwc := io.Pipe()
		go func() {
			defer pwc.Close()
			_, _ = pwc.Write(body)
		}()
		res.Body = prc
	}

	return res
}
