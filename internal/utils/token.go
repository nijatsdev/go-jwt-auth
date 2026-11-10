package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrAccessTokenInvalid = errors.New("access token is invalid")
	ErrAccessTokenExpired = errors.New("access token has expired")
)

// GenerateRawAndHashedTokens creates a new random token and its hashed version
func GenerateRawAndHashedTokens() (string, string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	rawToken := base64.RawStdEncoding.EncodeToString(bytes)
	hashedToken := HashToken(rawToken)
	return rawToken, hashedToken, nil
}

// HashToken returns the SHA-256 hash of the token encoded in base64
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

// GenerateAccessToken creates a new JWT access token
func GenerateAccessToken(
	userID uuid.UUID,
	userName, userEmail string,
	refreshTokenID uuid.UUID,
	ttl time.Duration,
	jwtSecret []byte,
	issuer, audience string,
) (token string, expirationTime time.Time, err error) {
	expirationTime = time.Now().Add(ttl)
	now := time.Now().Unix()

	claims := jwt.MapClaims{
		"sub":   userID.String(),
		"name":  userName,
		"email": userEmail,
		"exp":   expirationTime.Unix(),
		"iat":   now,
		"sid":   refreshTokenID.String(),
		"iss":   issuer,
		"aud":   audience,
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err = tokenObj.SignedString(jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expirationTime, nil
}

// ValidateAccessToken verifies a JWT token and returns the claims
func ValidateAccessToken(tokenString string, jwtSecret []byte, issuer, audience string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, ErrAccessTokenInvalid
		}
		return jwtSecret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrAccessTokenExpired
		}
		return nil, ErrAccessTokenInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrAccessTokenInvalid
	}

	if issuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != issuer {
			return nil, ErrAccessTokenInvalid
		}
	}
	if audience != "" {
		switch aud := claims["aud"].(type) {
		case string:
			if aud != audience {
				return nil, ErrAccessTokenInvalid
			}
		case []any:
			match := false
			for _, v := range aud {
				if s, ok := v.(string); ok && s == audience {
					match = true
					break
				}
			}
			if !match {
				return nil, ErrAccessTokenInvalid
			}
		default:
			return nil, ErrAccessTokenInvalid
		}
	}

	return claims, nil
}
