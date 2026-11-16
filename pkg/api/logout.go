package api

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"gorm.io/gorm/clause"
)

// backchannelLogoutTimeout bounds one back-channel logout delivery.
const backchannelLogoutTimeout = 5 * time.Second

// validLogoutURI accepts an absolute http(s) URL with a host and no fragment,
// for post-logout redirect, back-channel and front-channel logout URIs.
func validLogoutURI(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.Fragment == ""
}

// recordApplicationSession notes that userID signed into applicationID
// through the session sid, so a logout of that session can tell it.
func recordApplicationSession(sid string, userID, applicationID uuid.UUID) error {
	if sid == "" {
		return nil
	}
	db, err := getDB()
	if err != nil {
		return err
	}
	return db.Clauses(clause.OnConflict{DoNothing: true}).Create(&database.ApplicationSession{
		ApplicationSessionFields: models.ApplicationSessionFields{
			ID:            uuid.New(),
			SessionID:     sid,
			UserID:        userID,
			ApplicationID: applicationID,
		},
	}).Error
}

// endApplicationSessions tells the applications userIDs signed into through
// the session sid that they signed out. Applications with a back-channel
// logout URI are sent a logout token now; the front-channel logout URIs of the
// others are returned for the browser to load. The records are then dropped.
func endApplicationSessions(tokenServices *tokens.Services, sid string, userIDs []string) []string {
	frontchannel := []string{}
	if sid == "" || len(userIDs) == 0 {
		return frontchannel
	}
	db, err := getDB()
	if err != nil {
		log.Printf("logout: %v", err)
		return frontchannel
	}

	var sessions []database.ApplicationSession
	if err := db.Where("session_id = ? AND user_id IN ?", sid, userIDs).Find(&sessions).Error; err != nil {
		log.Printf("logout: loading the session's applications: %v", err)
		return frontchannel
	}

	issuer := tokenServices.JWT().Issuer()
	for _, session := range sessions {
		client, err := findOAuth2ClientByID(session.ApplicationID.String())
		if err != nil {
			continue
		}
		if uri := client.BackchannelLogoutURI; uri != "" {
			token, err := tokens.GenerateLogoutToken(tokenServices, session.ApplicationID.String(), session.UserID.String(), sid)
			if err != nil {
				log.Printf("logout: signing a logout token: %v", err)
			} else {
				go deliverLogoutToken(uri, token)
			}
		}
		if uri := client.FrontchannelLogoutURI; uri != "" {
			target, err := url.Parse(uri)
			if err != nil {
				continue
			}
			query := target.Query()
			query.Set("iss", issuer)
			query.Set("sid", sid)
			target.RawQuery = query.Encode()
			if !slices.Contains(frontchannel, target.String()) {
				frontchannel = append(frontchannel, target.String())
			}
		}
	}

	if err := db.Where("session_id = ? AND user_id IN ?", sid, userIDs).Delete(&database.ApplicationSession{}).Error; err != nil {
		log.Printf("logout: dropping the session's applications: %v", err)
	}
	return frontchannel
}

// deliverLogoutToken posts a logout token as Back-Channel Logout 1.0 section
// 2.5 describes.
// shortcut: one attempt, logged on failure; add retries with a queue if an
// application's logout must not be missed.
func deliverLogoutToken(uri, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), backchannelLogoutTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		log.Printf("logout: back-channel request to %s: %v", uri, err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("logout: back-channel delivery to %s: %v", uri, err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		log.Printf("logout: back-channel delivery to %s answered %d", uri, resp.StatusCode)
	}
}

// EndSessionRequest is an OpenID Connect RP-initiated logout request.
type EndSessionRequest struct {
	IDTokenHint           string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
}

// endSession is a validated EndSessionRequest.
type endSession struct {
	client *database.OauthClient
	// subject is the user the ID token hint names, if one was given.
	subject string
	// returnTo is the post-logout redirect URI with state, or "".
	returnTo string
}

// validateEndSession checks an RP-initiated logout request: the ID token hint
// must be one this instance issued (it may have expired), name client_id when
// both are given, and a post-logout redirect URI must be registered exactly
// for the client.
func validateEndSession(tokenServices *tokens.Services, req EndSessionRequest) (endSession, error) {
	var result endSession
	clientID := req.ClientID

	if req.IDTokenHint != "" {
		jwtManager := tokenServices.JWT()
		private, err := jwtManager.ParseTokenPrivateClaims(req.IDTokenHint)
		if err != nil || private.TokenType != tokens.TokenTypeIDToken {
			return result, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "id_token_hint is not a valid ID token")
		}
		var content tokens.IDTokenContent
		if err := jwtManager.ParseTokenCustomClaims(req.IDTokenHint, &content); err != nil || content.Issuer != jwtManager.Issuer() {
			return result, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "id_token_hint is not a valid ID token")
		}
		if clientID == "" && len(content.Audience) > 0 {
			clientID = content.Audience[0]
		} else if clientID != "" && !content.Audience.Contains(clientID) {
			return result, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "id_token_hint was not issued to client_id")
		}
		result.subject = content.Subject
	}

	if clientID != "" {
		client, err := findOAuth2ClientByID(clientID)
		if err != nil {
			return result, translateOAuth2ClientLookupError(err)
		}
		result.client = client
	}

	if req.PostLogoutRedirectURI != "" {
		if result.client == nil {
			return result, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "post_logout_redirect_uri needs client_id or id_token_hint")
		}
		if !slices.ContainsFunc(result.client.PostLogoutRedirectURIs, func(u database.OauthPostLogoutRedirectURI) bool {
			return u.URI == req.PostLogoutRedirectURI
		}) {
			return result, meilingErrors.NewOAuth2Error(meilingErrors.ErrInvalidRequest, "post_logout_redirect_uri is not registered for the client")
		}
		target, _ := url.Parse(req.PostLogoutRedirectURI)
		if req.State != "" {
			query := target.Query()
			query.Set("state", req.State)
			target.RawQuery = query.Encode()
		}
		result.returnTo = target.String()
	}
	return result, nil
}

// BuildEndSessionRedirectURL validates an RP-initiated logout request and
// returns the frontend URL that asks the user to confirm it.
func BuildEndSessionRedirectURL(cfg *config.MeilingConfig, tokenServices *tokens.Services, req EndSessionRequest) (string, error) {
	if _, err := validateEndSession(tokenServices, req); err != nil {
		return "", err
	}
	uri, err := oauth2Frontend(cfg)
	if err != nil {
		return "", err
	}

	values := uri.Query()
	values.Set("end_session", "1")
	for name, value := range map[string]string{
		"id_token_hint":            req.IDTokenHint,
		"client_id":                req.ClientID,
		"post_logout_redirect_uri": req.PostLogoutRedirectURI,
		"state":                    req.State,
	} {
		if value != "" {
			values.Set(name, value)
		}
	}
	uri.RawQuery = values.Encode()
	return uri.String(), nil
}

// EndSessionResult is where the browser goes after a confirmed logout.
type EndSessionResult struct {
	// RedirectURI is the client's post-logout redirect URI with state, or "".
	RedirectURI string `json:"redirectUri,omitempty"`
	// FrontchannelLogoutURIs are for the browser to load before leaving.
	FrontchannelLogoutURIs []string `json:"frontchannelLogoutUris"`
}

// EndSession carries out a confirmed RP-initiated logout: it signs out of
// session the user the ID token hint names, else userID, else every user, and
// tells the applications they signed into through it.
func EndSession(tokenServices *tokens.Services, session *tokens.SessionPayload, req EndSessionRequest, userID string) (EndSessionResult, error) {
	request, err := validateEndSession(tokenServices, req)
	if err != nil {
		return EndSessionResult{}, err
	}

	// The hint names the user to sign out; one not in this session leaves the
	// session as it is.
	var users []string
	switch {
	case request.subject != "":
		if slices.Contains(session.Users, request.subject) {
			users = []string{request.subject}
		}
	case slices.Contains(session.Users, userID):
		users = []string{userID}
	default:
		users = slices.Clone(session.Users)
	}

	for _, user := range users {
		session.SignOut(user)
	}
	if err := session.Update(tokenServices.Session()); err != nil {
		return EndSessionResult{}, meilingErrors.NewInternalServerError("failed to update session", err)
	}
	ids := make([]uuid.UUID, 0, len(users))
	for _, user := range users {
		if id, err := uuid.Parse(user); err == nil {
			ids = append(ids, id)
		}
	}
	_ = MarkSignOut(session, ids...)

	return EndSessionResult{
		RedirectURI:            request.returnTo,
		FrontchannelLogoutURIs: endApplicationSessions(tokenServices, session.SID, users),
	}, nil
}
