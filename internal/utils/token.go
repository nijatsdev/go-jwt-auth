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
func GenerateAccessToken(userID uuid.UUID, userName, userEmail string, refreshTokenID uuid.UUID, ttl time.Duration, jwtSecret []byte) (token string, expirationTime time.Time, err error) {
	expirationTime = time.Now().Add(ttl)

	claims := jwt.MapClaims{
		"sub":   userID.String(),
		"name":  userName,
		"email": userEmail,
		"exp":   expirationTime.Unix(),
		"iat":   time.Now().Unix(),
		"sid":   refreshTokenID.String(),
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err = tokenObj.SignedString(jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expirationTime, nil
}

// ValidateAccessToken verifies a JWT token and returns the claims
func ValidateAccessToken(tokenString string, jwtSecret []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrAccessTokenInvalid
		}
		return jwtSecret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrAccessTokenExpired
		}
		return nil, ErrAccessTokenInvalid
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrAccessTokenInvalid
}
