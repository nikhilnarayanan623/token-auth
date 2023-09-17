package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/nikhilnarayanan623/token-auth/token"
	"github.com/stretchr/testify/assert"
)

func TestGenerateToken(t *testing.T) {

	tests := map[string]struct {
		input           token.Payload
		expectingOutput bool
		expectedError   error
	}{
		"expired_time_should_return_error": {
			input: token.Payload{
				ExpireAt: time.Date(2000, 0, 0, 0, 0, 0, 0, time.Local),
			},
			expectingOutput: false,
			expectedError:   ErrInvalidExpireTime,
		},
		"successful_payload_should_return_token": {
			input: token.Payload{
				UserID:   12,
				ExpireAt: time.Now().Add(time.Hour),
				Email:    "email@email.com",
				Role:     "admin",
			},
			expectingOutput: true,
			expectedError:   nil,
		},
	}

	for name, test := range tests {

		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tokenAuth := NewJwtTokenAuth("key")

			actualOutput, actualError := tokenAuth.GenerateToken(test.input)

			assert.Equal(t, test.expectedError, actualError)

			if test.expectingOutput {
				assert.NotEmpty(t, actualOutput)
			} else {
				assert.Empty(t, actualOutput)
			}
		})
	}

}

func TestVerifyToken(t *testing.T) {

	jwtKey := "key"
	validExpireTime := time.Now().Add(time.Hour)

	tests := map[string]struct {
		expectedOutput token.Payload
		buildStub      func(t *testing.T) (tokenString string)
		expectedError  error
	}{
		"invalid_token_should_return_token_invalid_error": {
			expectedOutput: token.Payload{},
			buildStub: func(_ *testing.T) string {
				return "invalid_token"
			},
			expectedError: ErrInvalidToken,
		},

		"invalid_sign_method_should_return_error": {
			expectedOutput: token.Payload{},
			buildStub: func(t *testing.T) string {

				tkn := jwt.NewWithClaims(jwt.SigningMethodNone, &jwtClaims{
					ExpiresAt: time.Now().Add(time.Hour),
				})

				tokenString, err := tkn.SignedString(jwt.UnsafeAllowNoneSignatureType)
				assert.NoError(t, err)

				return tokenString
			},
			expectedError: ErrInvalidToken,
		},
		"expired_token_should_return_error_expired": {
			expectedOutput: token.Payload{},
			buildStub: func(t *testing.T) (tokenString string) {

				expiredClaims := jwtClaims{
					ExpiresAt: time.Date(2000, 0, 0, 0, 0, 0, 0, time.Local), // an expired time
				}
				tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, &expiredClaims)

				tokenString, err := tkn.SignedString([]byte(jwtKey))
				assert.NoError(t, err)

				return tokenString
			},
			expectedError: ErrExpiredToken,
		},
		"valid_token_should_return_payload": {
			expectedOutput: token.Payload{
				UserID:   "user_id",
				ExpireAt: validExpireTime,
			},
			buildStub: func(t *testing.T) (tokenString string) {

				validClaims := jwtClaims{
					ExpiresAt: validExpireTime,
					UserID:    "user_id",
				}
				tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, &validClaims)

				tokenString, err := tkn.SignedString([]byte(jwtKey))
				assert.NoError(t, err)

				return tokenString
			},
		},
	}

	for name, test := range tests {

		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tokenString := test.buildStub(t)

			tokenAuth := NewJwtTokenAuth(jwtKey)

			actualOutput, actualError := tokenAuth.VerifyToken(tokenString)

			assert.Equal(t, test.expectedError, actualError)

			assert.Equal(t, test.expectedOutput.UserID, actualOutput.UserID)

		})
	}
}
