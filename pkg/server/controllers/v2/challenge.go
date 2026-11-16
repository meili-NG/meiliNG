package v2

import (
	"context"

	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/server/controllers"
)

// ChallengeController handles challenge-related operations
type ChallengeController struct {
	controllers.Base
}

// NewChallengeController creates a new challenge controller
func NewChallengeController(a *app.Meiling) *ChallengeController {
	return &ChallengeController{Base: controllers.NewBase(a)}
}

func (c *ChallengeController) HandleGetChallenge(ctx context.Context, input *GetChallengeInput) (*GetChallengeOutput, error) {
	result, err := api.GetChallengeTypes(c.TokenServices(), input.Token, input.For)
	if err != nil {
		return nil, err
	}

	return &GetChallengeOutput{Body: result}, nil
}

func (c *ChallengeController) HandleIssueChallenge(ctx context.Context, input *IssueChallengeInput) (*IssueChallengeOutput, error) {
	result, err := api.IssueChallenge(c.TokenServices(), input.Token, input.Type, input.For)
	if err != nil {
		return nil, err
	}

	return &IssueChallengeOutput{Body: ChallengeIssuedPayload{
		Challenge: result.Challenge,
		ExpiresIn: result.ExpiresIn,
	}}, nil
}

func (c *ChallengeController) HandleValidateChallenge(ctx context.Context, input *ValidateChallengeInput) (*ValidateChallengeOutput, error) {
	result, err := api.ValidateChallenge(c.TokenServices(), input.Token, input.Type, input.For, input.Body.Response)
	if err != nil {
		return nil, err
	}

	return &ValidateChallengeOutput{Body: ChallengeSuccessPayload{
		Passed: result.Passed,
	}}, nil
}
