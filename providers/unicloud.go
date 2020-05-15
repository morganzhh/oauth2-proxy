package providers

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

type UniCloudProvider struct {
	*ProviderData
	roles  []string
	server string
}

func (p *UniCloudProvider) SetRoles(roles []string) {
	p.roles = roles
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

	listRoles := make([]string, 10)
	for _, role := range roles {
		listRoles = append(listRoles, role.(map[string]interface{})["name"].(string))
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

func (p *UniCloudProvider) ValidateGroup(roles string) bool {
	// if none provided, all login users can access
	if len(p.roles) == 0 {
		return true
	}

	for _, role := range strings.Split(roles, ":") {
		if itemExists(p.roles, role) {
			return true
		}
	}
	return false
}

func (p *UniCloudProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, getUniCloudHeader(s.AccessToken))
}

func itemExists(slice interface{}, item interface{}) bool {
	s := reflect.ValueOf(slice)

	if s.Kind() != reflect.Slice {
		panic("Invalid data-type")
	}

	for i := 0; i < s.Len(); i++ {
		if s.Index(i).Interface() == item {
			return true
		}
	}

	return false
}

func getUniCloudHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Authorization", fmt.Sprintf("token %s", accessToken))
	return header
}
