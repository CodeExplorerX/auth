package main

import (
	"errors"
	"net/http"
)

var errAuth = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		return errAuth
	}

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return errAuth
	}

	csrf := r.Header.Get("X-CSRF-TOKEN")
	if csrf != user.CSRFToken || csrf == "" {
		return errAuth
	}

	return nil
}
