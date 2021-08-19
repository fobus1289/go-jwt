package jwt

import (
	"errors"
	goJwt "github.com/dgrijalva/jwt-go"
)

var invalidToken = errors.New("invalid token")

func Encode(claims goJwt.Claims) (*goJwt.Token, error) {
	token := goJwt.NewWithClaims(goJwt.SigningMethodHS256, claims)
	return token, nil
}

func DecodeWithExpired(token string, claims goJwt.Claims, secret []byte) (*goJwt.Token, error) {

	var jwtToken, err = goJwt.ParseWithClaims(token, claims, func(token *goJwt.Token) (interface{}, error) {

		if _, isValid := token.Method.(*goJwt.SigningMethodHMAC); !isValid {
			return nil, invalidToken
		}

		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	if !jwtToken.Valid {
		return nil, invalidToken
	}

	return jwtToken, nil
}
