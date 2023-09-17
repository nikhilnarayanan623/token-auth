package token

import (
	"errors"
	"time"
)

// Interface of token based authentication
type TokenAuth interface {
	GenerateToken(req Payload) (TokenResponse, error)
	VerifyToken(tokenString string) (Payload, error)
}

// Data stored in token
type Payload struct {
	TokenID  string // if not provided by user will create random id
	UserID   interface{}
	Email    string
	Role     string
	ExpireAt time.Time
}

// Response for the token generate
type TokenResponse struct {
	TokenID     string
	TokenString string
}

// Get the payload user id as uid
func (p *Payload) GetUserIdAsUint() (uint, error) {

	uid, ok := p.UserID.(uint)
	if !ok {
		return 0, errors.New("user id is not uint")
	}
	return uid, nil
}

// Get the payload user id as string
func (p *Payload) GetUserIdAsString() (string, error) {

	str, ok := p.UserID.(string)
	if !ok {
		return "", errors.New("user id is not uint")
	}
	return str, nil
}
