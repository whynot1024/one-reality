package asn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchPrefixesNormalizesAndDeduplicates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("resource"); got != "AS15169" {
			t.Fatalf("resource = %q, want AS15169", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"prefixes":[{"prefix":"1.1.1.1/24"},{"prefix":"1.1.1.0/24"},{"prefix":"bad"}]}}`))
	}))
	defer server.Close()

	client := NewClient()
	client.endpoint = server.URL
	got, err := client.FetchPrefixes(context.Background(), "15169")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "1.1.1.0/24" {
		t.Fatalf("prefixes = %#v", got)
	}
}
