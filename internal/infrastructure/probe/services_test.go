package probe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
)

func TestInterpretVaultAndES(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/sys/health") {
			w.Write([]byte(`{"initialized":true,"sealed":true,"standby":false,"version":"1.17.2","cluster_name":"vault-a"}`))
			return
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()
	hc := httpClient()
	code, body, err := get(hc, srv.URL+healthPaths["vault"][0])
	if err != nil {
		t.Fatal(err)
	}
	ck := inventory.ServiceCheck{Kind: "vault", Endpoint: srv.URL, Facts: map[string]string{}}
	interpret(&ck, "/v1/sys/health", code, body)
	if ck.Facts["sealed"] != "true" || ck.Facts["version"] != "1.17.2" || len(ck.Notes) < 2 {
		t.Fatalf("vault: %+v", ck)
	}
	code, body, _ = get(hc, srv.URL+"/")
	es := inventory.ServiceCheck{Kind: "elasticsearch", Facts: map[string]string{}}
	interpret(&es, "/", code, body)
	if !strings.HasPrefix(es.Auth, "authentication required") {
		t.Fatalf("es: %+v", es)
	}
}
