package quiltro

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const googleUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"

// GoogleProvider builds an OAuthProvider wired to Google's OAuth 2.0 /
// OpenID Connect endpoints. scopes defaults to openid, email, profile when
// none are given.
func GoogleProvider(clientID, clientSecret, redirectURL string, scopes ...string) OAuthProvider {
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	return OAuthProvider{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint:     google.Endpoint,
		},
		FetchProfile: fetchGoogleProfile,
	}
}

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func fetchGoogleProfile(ctx context.Context, token *oauth2.Token) (OAuthProfile, error) {
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserInfoURL, nil)
	if err != nil {
		return OAuthProfile{}, fmt.Errorf("build google userinfo request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return OAuthProfile{}, fmt.Errorf("fetch google userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return OAuthProfile{}, fmt.Errorf("google userinfo returned status %d", resp.StatusCode)
	}

	var info googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return OAuthProfile{}, fmt.Errorf("decode google userinfo: %w", err)
	}

	return OAuthProfile{
		Subject:       info.Sub,
		Email:         info.Email,
		EmailVerified: info.EmailVerified,
		Name:          info.Name,
		Picture:       info.Picture,
	}, nil
}
