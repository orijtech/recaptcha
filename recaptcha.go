package recaptcha

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Request struct {
	sync.RWMutex

	SecretKey string `json:"secret"`
	Response  string `json:"response"`
	RemoteIP  string `json:"remoteip,omitempty"`

	Transport http.RoundTripper `json:"-"`
}

func (req *Request) httpClient() *http.Client {
	req.RLock()
	defer req.RUnlock()

	if req.Transport == nil {
		return http.DefaultClient
	}

	return &http.Client{
		Transport: req.Transport,
	}
}

type Response struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`

	ChallengeTimeStamp *time.Time `json:"challenge_ts"`
}

const verifyURL = "https://www.google.com/recaptcha/api/siteverify"

var (
	errEmptySecretKey = errors.New("empty secretKey")
	errEmptyResponse  = errors.New("empty response")
	errNilRequest     = errors.New("nil request cannot be validated")
)

func (req *Request) Validate() error {
	req.RLock()
	defer req.RUnlock()

	if req.SecretKey == "" {
		return errEmptySecretKey
	}
	if req.Response == "" {
		return errEmptyResponse
	}
	return nil
}

func (req *Request) Verify() (*Response, error) {
	if req == nil {
		return nil, errNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	// The recaptcha documentation claims POST parameters
	// but actually it takes in Query string keys and values
	// so need to transform the request into url.Values then .Encode()
	// Contrary to the claims at https://developers.google.com/recaptcha/docs/verify
	// See https://twitter.com/odeke_et/status/846786233221222400.
	blob, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	asMap := make(map[string]string)
	_ = json.Unmarshal(blob, &asMap)

	hdr := make(url.Values)
	for key, value := range asMap {
		hdr.Add(key, value)
	}
	finalURL := fmt.Sprintf("%s?%s", verifyURL, hdr.Encode())

	// As of Go1.8, using http.NoBody instead of nil, http.Transport
	// doesn't recognize http.NoBody.
	// See https://github.com/golang/go/issues/18891
	// TODO: Use http.NoBody once that bug is fixed.
	httpReq, _ := http.NewRequest("POST", finalURL, nil)
	httpClient := req.httpClient()
	httpRes, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	if httpRes.Body != nil {
		defer httpRes.Body.Close()
	}

	if !statusOK(httpRes.StatusCode) {
		return nil, errors.New(httpRes.Status)
	}

	resBlob, err := ioutil.ReadAll(httpRes.Body)
	if err != nil {
		return nil, err
	}

	res := new(Response)
	if err := json.Unmarshal(resBlob, res); err != nil {
		return nil, err
	}

	return res, nil
}

func statusOK(code int) bool { return code >= 200 && code <= 299 }
