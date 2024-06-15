package auth

import (
	"errors"
	"net/http"
	"testing"
)


func TestGetAPIKey(t *testing.T) {
    tests := []struct {
        name       string
        headers    http.Header
        want       string
        wantErr    error
    }{
        {
            name:       "No Authorization Header",
            headers:    http.Header{},
            want:       "",
            wantErr:    ErrNoAuthHeaderIncluded,
        },
        {
            name:       "Malformed Authorization Header - Missing ApiKey",
            headers:    http.Header{"Authorization": []string{"Bearer abcdef"}},
            want:       "",
            wantErr:    errors.New("malformed authorization header"),
        },
        {
            name:       "Malformed Authorization Header - Missing Token",
            headers:    http.Header{"Authorization": []string{"ApiKey"}},
            want:       "",
            wantErr:    errors.New("malformed authorization header"),
        },
        {
            name:       "Valid Authorization Header",
            headers:    http.Header{"Authorization": []string{"ApiKey abcdef"}},
            want:       "abcdef",
            wantErr:    nil,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := GetAPIKey(tt.headers)
            if got != tt.want {
                t.Errorf("GetAPIKey() got = %v, want %v", got, tt.want)
            }
            if err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
                t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
            }
            if (err != nil && tt.wantErr == nil) || (err == nil && tt.wantErr != nil) {
                t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
