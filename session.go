package main

import (
	"errors"
	"net/http"
)

var authError = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		return authError
	}

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return authError
	}

	csrf := r.Header.Get("X-CSRF-TOKEN")
	if csrf != user.CSRFToken || csrf == "" {
		return authError
	}

	return nil
}
