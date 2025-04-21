package http_client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/RexArseny/goph_keeper/internal/server/middlewares"
	"github.com/RexArseny/goph_keeper/internal/server/models"
)

type HTTPClient struct {
	address string
	client  *http.Client
}

func NewHTTPClient(address string) HTTPClient {
	return HTTPClient{
		address: address,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:    30,
				IdleConnTimeout: 15 * time.Second,
			},
		},
	}
}

func (c *HTTPClient) Registration(request models.AuthRequest) (*string, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("can not marshal reuqest: %w", err)
	}

	resp, err := c.client.Post(c.address+"/registration", "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("can not send request for registration: %w", err)
	}

	if resp.StatusCode == http.StatusConflict {
		return nil, errors.New("this user already exist")
	}

	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can not read response body: %w", err)
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("can not close response body: %w", err)
	}

	var jwt models.AuthResponse
	err = json.Unmarshal(resultBody, &jwt)
	if err != nil {
		return nil, fmt.Errorf("can not unmarshal body: %w", err)
	}

	return &jwt.JWT, nil
}

func (c *HTTPClient) Auth(request models.AuthRequest) (*string, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("can not marshal reuqest: %w", err)
	}

	resp, err := c.client.Post(c.address+"/auth", "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("can not send request for auth: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("invalid username or password")
	}

	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can not read response body: %w", err)
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("can not close response body: %w", err)
	}

	var jwt models.AuthResponse
	err = json.Unmarshal(resultBody, &jwt)
	if err != nil {
		return nil, fmt.Errorf("can not unmarshal body: %w", err)
	}

	return &jwt.JWT, nil
}

func (c *HTTPClient) Sync(request models.UserData, jwt string) error {
	data, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("can not marshal reuqest: %w", err)
	}

	req, err := http.NewRequest("POST", c.address+"/sync", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("can not create request: %w", err)
	}
	req.Header.Add(middlewares.Authorization, "Bearer "+jwt)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("can not send request for sync: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func (c *HTTPClient) Get(jwt string) (*models.UserData, error) {
	req, err := http.NewRequest("GET", c.address+"/get", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("can not create request: %w", err)
	}
	req.Header.Add(middlewares.Authorization, "Bearer "+jwt)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can not send request for get: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can not read response body: %w", err)
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("can not close response body: %w", err)
	}

	var data models.UserData
	err = json.Unmarshal(resultBody, &data)
	if err != nil {
		return nil, fmt.Errorf("can not unmarshal body: %w", err)
	}

	return &data, nil
}
