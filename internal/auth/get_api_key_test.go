package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestApiKeyExists(t *testing.T) {
	header := http.Header{}

	header.Set("Authorization", "ApiKey test_key")
	got, err := GetAPIKey(header)

	want := "test_key"

	if err != nil {
		t.Fatalf("Encountered error: %v", err)
	}
	if want != got {
		t.Fatalf("expected: %s, got: %s", want, got)
	}
}

func TestApiKeyMalformed(t *testing.T) {
	header := http.Header{}

	header.Set("Authorization", "bad_key")

	_, err := GetAPIKey(header)
	want := "malformed authorization header"

	if err == nil {
		t.Fatalf("Expected error and got none")
	}

	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected: %s, got: %s", want, err)
	}

}

func TestApiKeyMissing(t *testing.T) {
	header := http.Header{}

	_, err := GetAPIKey(header)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}
