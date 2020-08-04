package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

type ProxyAuth struct {
	Upstream      url.URL
	GuestRoleName string
	GuestUser     string
	GuestPassword string
	AdminRoleName string
	AdminUser     string
	AdminPassword string
}

type UniCloudProvider struct {
	*ProviderData
	upstreams []ProxyAuth
	server    string
}

func (p *UniCloudProvider) SetUpstreams(upstreams []options.ProxyAuth) {
	p.upstreams = mapping(upstreams)
}

func (p *UniCloudProvider) SetServer(server string) {
	p.server = server
}

func NewUniCloudProvider(p *ProviderData) *UniCloudProvider {
	p.ProviderName = "UniCloud"
	return &UniCloudProvider{ProviderData: p}
}

func (p *UniCloudProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.ValidateURL.String(), nil)
	if err != nil {
		logger.Printf("failed building request %s", err)
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	json, err := requests.Request(req)
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	roles, err := json.Get("roles").Array()
	if err != nil {
		logger.Printf("error on getting roles %s", err)
		return "", err
	}

	listRoles := make([]string, len(roles))
	for i, role := range roles {
		listRoles[i] = role.(map[string]interface{})["name"].(string)
	}
	return strings.Join(listRoles, ":"), err
}

// GetUserName returns the Account username
func (p *UniCloudProvider) GetUserName(ctx context.Context, s *sessions.SessionState) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.ValidateURL.String(), nil)
	if err != nil {
		logger.Printf("failed building request %s", err)
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	json, err := requests.Request(req)
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	return json.Get("username").String()
}

// GetPreferredUsername returns the Account preferred username
func (p *UniCloudProvider) GetPreferredUsername(ctx context.Context, s *sessions.SessionState) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.ValidateURL.String(), nil)
	if err != nil {
		logger.Printf("failed building request %s", err)
		return "", err
	}
	req.Header = getUniCloudHeader(s.AccessToken)
	json, err := requests.Request(req)
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	return json.Get("name").String()
}

func (p *UniCloudProvider) ValidateRedirect(requestURI string, s *sessions.SessionState) bool {
	cfg := getProxyCfg(p.upstreams, requestURI)
	if cfg == nil {
		return false
	}
	roles := strings.Split(s.Email, ",")[0]
	loginRole := ""
	login := false
	for _, role := range strings.Split(roles, ":") {
		if role == cfg.GuestRoleName {
			login = true
			loginRole = "user"
		}
		// in case of user has both admin and user role
		if role == cfg.AdminRoleName {
			login = true
			loginRole = "admin"
			break
		}
	}
	if login {
		s.Email = strings.Join([]string{roles, loginRole}, ",")
	}
	return login
}

func (p *UniCloudProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, getUniCloudHeader(s.AccessToken))
}

func (p *UniCloudProvider) GetBasicUser(requestURI string, s *sessions.SessionState) (string, string) {
	cfg := getProxyCfg(p.upstreams, requestURI)
	if nil != cfg {
		emailExt := strings.Split(s.Email, ",")
		if len(emailExt) == 2 {
			if emailExt[1] == "admin" {
				return cfg.AdminUser, cfg.AdminPassword
			} else if emailExt[1] == "user" {
				return cfg.GuestUser, cfg.GuestPassword
			}
		}
	}
	return "", ""
}

func getProxyCfg(cfgs []ProxyAuth, requestURI string) *ProxyAuth {
	for _, cfg := range cfgs {
		if strings.HasPrefix(requestURI, cfg.Upstream.Path) {
			return &cfg
		}
	}
	return nil
}

//func itemExists(slice interface{}, item interface{}) bool {
//	s := reflect.ValueOf(slice)
//
//	if s.Kind() != reflect.Slice {
//		panic("Invalid data-type")
//	}
//
//	for i := 0; i < s.Len(); i++ {
//		if s.Index(i).Interface() == item {
//			return true
//		}
//	}
//
//	return false
//}

func getUniCloudHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

func mapping(opts []options.ProxyAuth) []ProxyAuth {
	uni := make([]ProxyAuth, len(opts))
	for i, opt := range opts {
		path, err := url.Parse(opt.Upstream)
		if nil == err {
			uni[i].Upstream = *path
			uni[i].AdminPassword = opt.AdminPassword
			uni[i].AdminRoleName = opt.AdminRoleName
			uni[i].AdminUser = opt.AdminUser
			uni[i].GuestPassword = opt.GuestPassword
			uni[i].GuestRoleName = opt.GuestRoleName
			uni[i].GuestUser = opt.GuestUser
		}
	}
	return uni
}
