package http_client

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RexArseny/goph_keeper/internal/server/middlewares"
	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/stretchr/testify/assert"
)

func TestNewHTTPClient(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		expected HTTPClient
	}{
		{
			name:    "valid address",
			address: "https://localhost:8080",
			expected: HTTPClient{
				address: "https://localhost:8080",
				client: &http.Client{
					Timeout: 0,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
						MaxIdleConns:    30,
						IdleConnTimeout: 15 * time.Second,
					},
				},
			},
		},
		{
			name:    "empty address",
			address: "",
			expected: HTTPClient{
				address: "",
				client: &http.Client{
					Timeout: 0,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
						MaxIdleConns:    30,
						IdleConnTimeout: 15 * time.Second,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewHTTPClient(tt.address)
			assert.Equal(t, tt.expected.address, client.address)
			assert.NotNil(t, client.client)
			assert.IsType(t, &http.Transport{}, client.client.Transport)

			transport := client.client.Transport.(*http.Transport)
			assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
			assert.Equal(t, 30, transport.MaxIdleConns)
			assert.Equal(t, 15*time.Second, transport.IdleConnTimeout)
		})
	}
}

func TestHTTPClientRegistration(t *testing.T) {
	tests := []struct {
		name          string
		request       models.AuthRequest
		serverHandler http.HandlerFunc
		expectedJWT   string
		expectedError string
	}{
		{
			name: "successful registration",
			request: models.AuthRequest{
				Username: "username",
				Password: "password",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/registration", r.URL.Path)
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				var req models.AuthRequest
				err := json.NewDecoder(r.Body).Decode(&req)
				assert.NoError(t, err)
				assert.Equal(t, "username", req.Username)
				assert.Equal(t, "password", req.Password)

				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(models.AuthResponse{JWT: "test-jwt"})
			},
			expectedJWT: "test-jwt",
		},
		{
			name: "user already exists",
			request: models.AuthRequest{
				Username: "username",
				Password: "password",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusConflict)
			},
			expectedError: "this user already exist",
		},
		{
			name: "invalid response body",
			request: models.AuthRequest{
				Username: "username",
				Password: "password",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("invalid json"))
			},
			expectedError: "can not unmarshal body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			client := NewHTTPClient(server.URL)
			jwt, err := client.Registration(tt.request)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, jwt)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, jwt)
				assert.Equal(t, tt.expectedJWT, *jwt)
			}
		})
	}
}

func TestHTTPClientAuth(t *testing.T) {
	tests := []struct {
		name          string
		request       models.AuthRequest
		serverHandler http.HandlerFunc
		expectedJWT   string
		expectedError string
	}{
		{
			name: "successful authentication",
			request: models.AuthRequest{
				Username: "username",
				Password: "password",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/auth", r.URL.Path)
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				var req models.AuthRequest
				err := json.NewDecoder(r.Body).Decode(&req)
				assert.NoError(t, err)
				assert.Equal(t, "username", req.Username)
				assert.Equal(t, "password", req.Password)

				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(models.AuthResponse{JWT: "auth-jwt"})
			},
			expectedJWT: "auth-jwt",
		},
		{
			name: "invalid credentials",
			request: models.AuthRequest{
				Username: "username",
				Password: "password",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			expectedError: "invalid username or password",
		},
		{
			name: "server error",
			request: models.AuthRequest{
				Username: "username",
				Password: "password",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "can not unmarshal body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			client := NewHTTPClient(server.URL)
			jwt, err := client.Auth(tt.request)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, jwt)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, jwt)
				assert.Equal(t, tt.expectedJWT, *jwt)
			}
		})
	}
}

func TestHTTPClientSync(t *testing.T) {
	tests := []struct {
		name          string
		request       models.UserData
		jwt           string
		serverHandler http.HandlerFunc
		expectedError string
	}{
		{
			name: "successful sync",
			request: models.UserData{
				Texts: []models.Text{{Text: "text"}},
			},
			jwt: "valid-jwt",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/sync", r.URL.Path)
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "Bearer valid-jwt", r.Header.Get(middlewares.Authorization))

				var data models.UserData
				err := json.NewDecoder(r.Body).Decode(&data)
				assert.NoError(t, err)
				assert.Len(t, data.Texts, 1)
				assert.Equal(t, "text", data.Texts[0].Text)

				w.WriteHeader(http.StatusOK)
			},
		},
		{
			name:    "unauthorized",
			request: models.UserData{},
			jwt:     "invalid-jwt",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			expectedError: "unexpected status code: 401",
		},
		{
			name:    "server error",
			request: models.UserData{},
			jwt:     "valid-jwt",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "unexpected status code: 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			client := NewHTTPClient(server.URL)
			err := client.Sync(tt.request, tt.jwt)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHTTPClientGet(t *testing.T) {
	tests := []struct {
		name          string
		jwt           string
		serverHandler http.HandlerFunc
		expectedData  *models.UserData
		expectedError string
	}{
		{
			name: "successful get",
			jwt:  "valid-jwt",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/get", r.URL.Path)
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "Bearer valid-jwt", r.Header.Get(middlewares.Authorization))

				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(models.UserData{})
			},
			expectedData: &models.UserData{},
		},
		{
			name: "unauthorized",
			jwt:  "invalid-jwt",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			expectedError: "unexpected status code: 401",
		},
		{
			name: "invalid response",
			jwt:  "valid-jwt",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("invalid json"))
			},
			expectedError: "can not unmarshal body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			client := NewHTTPClient(server.URL)
			data, err := client.Get(tt.jwt)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, data)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, data)
				assert.Equal(t, tt.expectedData, data)
			}
		})
	}
}
