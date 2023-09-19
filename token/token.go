package token

import (
	"errors"
	"time"
)

// Interface of token-based authentication
type TokenAuth interface {
	GenerateToken(req Payload) (TokenResponse, error)
	VerifyToken(tokenString string) (Payload, error)
}

// Data stored in token
type Payload struct {
	TokenID  string // if not provided by the user will create a random id
	UserID   interface{}
	Email    string
	Role     string
	ExpireAt time.Time
}

// Response for the token generated
type TokenResponse struct {
	TokenID     string
	TokenString string
}

// Get the payload user id as uid
func (p *Payload) GetUserIdAsUint() (uint, error) {

	uid, ok := p.UserID.(uint)
	if !ok {
		return 0, errors.New("user id is not in uint")
	}
	return uid, nil
}

// Get the payload user id as a string
func (p *Payload) GetUserIdAsString() (string, error) {

	str, ok := p.UserID.(string)
	if !ok {
		return "", errors.New("user id is not in string")
	}
	return str, nil
}
