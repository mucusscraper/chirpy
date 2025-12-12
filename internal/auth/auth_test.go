package auth

import (
	"testing"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "supersecret123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if hash == "" {
		t.Fatalf("expected a non-empty hash")
	}
	if hash == password {
		t.Fatalf("hash should never be equal to the password")
	}
}
func TestCheckPasswordHashCorrect(t *testing.T) {
	password := "myPassword!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	valid, err := CheckPasswordHash(password, hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash returned error: %v", err)
	}
	if !valid {
		t.Fatalf("expected password to validate, but got false")
	}
}
func TestCheckPasswordHashIncorrect(t *testing.T) {
	password := "correctPass"
	wrongPassword := "wrongPass"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	valid, err := CheckPasswordHash(wrongPassword, hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash returned error: %v", err)
	}
	if valid {
		t.Fatalf("expected false for wrong password, got true")
	}
}
func TestCheckPasswordHashInvalidHash(t *testing.T) {
	password := "test123"
	invalidHash := "this-is-not-a-valid-argon-hash"

	valid, err := CheckPasswordHash(password, invalidHash)
	if err == nil {
		t.Fatalf("expected error for invalid hash format, got nil")
	}
	if valid {
		t.Fatalf("expected valid=false when hash is invalid")
	}
}

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "super-secret-key"
	token, err := MakeJWT(userID, secret)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}
	parsedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT returned error: %v", err)
	}
	if parsedID != userID {
		t.Fatalf("expected ID %v, got %v", userID, parsedID)
	}
}

func TestValidateJWTExpired(t *testing.T) {
	userID := uuid.New()
	secret := "super-secret-key"
	token, err := MakeJWT(userID, secret)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Fatalf("expected error for expired token, got nil")
	}
}
func TestValidateJWTWrongSecret(t *testing.T) {
	userID := uuid.New()
	secret := "correct-secret"
	wrongSecret := "wrong-secret"

	token, err := MakeJWT(userID, secret)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Fatalf("expected error for wrong signing secret, got nil")
	}
}
