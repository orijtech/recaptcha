package recaptcha

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"
)

type Request struct {
	SecretKey string `json:"secret"`
	Response  string `json:"response"`
	RemoteIP  string `json:"remoteip,omitempty"`
}

type Response struct {
	Success            bool          `json:"success"`
	ChallengeTimeStamp *time.Time    `json:"challenge_ts"`
	ErrorCodes         []interface{} `json:"error-codes"`
}

const verifyURL = "https://www.google.com/recaptcha/api/siteverify"

func (req *Request) Verify() (*Response, error) {
	blob, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, _ := http.NewRequest("POST", verifyURL, bytes.NewReader(blob))
	httpRes, err := http.DefaultClient.Do(httpReq)
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
