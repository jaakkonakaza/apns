package apns2

import "net/http"

// HTTPClientForTesting exposes transport internals to the external transport tests.
func HTTPClientForTesting(client *Client) *http.Client { return client.httpClient }
