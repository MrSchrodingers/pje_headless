package pjeoffice_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MrSchrodingers/pje_headless/internal/pjeoffice"
	"github.com/MrSchrodingers/pje_headless/internal/signer"
)

// fakeSigner is a deterministic test double that satisfies signer.Signer.
// It records calls to Login so tests can assert the method was invoked.
type fakeSigner struct {
	sig      string
	chain    string
	loginErr error
	signErr  error
	loginCalled bool
}

func (f *fakeSigner) Login(_ context.Context) error {
	f.loginCalled = true
	return f.loginErr
}
func (f *fakeSigner) Sign(_ context.Context, _, _ string) (string, error) {
	return f.sig, f.signErr
}
func (f *fakeSigner) CertChainPKIPath(_ context.Context) (string, error) {
	return f.chain, nil
}
func (f *fakeSigner) Identity(_ context.Context) (signer.Identity, error) {
	return signer.Identity{Subject: "fake"}, nil
}
func (f *fakeSigner) Available(_ context.Context) bool { return true }

// TestHealthGET verifica que GET /pjeOffice/ devolve 200 com exatamente os bytes de gifOK.
func TestHealthGET(t *testing.T) {
	srv := pjeoffice.NewServer(&fakeSigner{sig: "X", chain: "Y"}, "0", "127.0.0.1")

	req := httptest.NewRequest(http.MethodGet, "/pjeOffice/", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("health: want 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "image/gif") {
		t.Fatalf("health: want image/gif, got %q", ct)
	}
	if got, want := rr.Body.Bytes(), pjeoffice.GifOK(); !bytes.Equal(got, want) {
		t.Fatalf("health: body bytes mismatch: got %x, want %x", got, want)
	}
}

// TestOptionsPreflightCORS verifica que OPTIONS retorna 204 com os headers CORS
// incluindo Access-Control-Allow-Private-Network.
func TestOptionsPreflightCORS(t *testing.T) {
	srv := pjeoffice.NewServer(&fakeSigner{sig: "X", chain: "Y"}, "0", "127.0.0.1")

	req := httptest.NewRequest(http.MethodOptions, "/pjeOffice/requisicao/", nil)
	req.Header.Set("Origin", "https://pje.jus.br")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS: want 204, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Private-Network") != "true" {
		t.Fatal("OPTIONS: missing Access-Control-Allow-Private-Network: true")
	}
	if rr.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatal("OPTIONS: missing Access-Control-Allow-Origin header")
	}
}

// TestRequisicaoPOSTAssinaEEnvia verifica o comportamento central do protocolo:
// dado um envelope POST em /pjeOffice/requisicao/, o servidor deve:
//  1. Chamar Login() no signer.
//  2. Chamar Sign(mensagem, algoritmo) e CertChainPKIPath().
//  3. Fazer POST ao endpoint "servidor+enviarPara" com o body
//     {"uuid": token, "mensagem": ..., "assinatura": ..., "certChain": ...}.
//  4. Retornar 200 com GIF ao cliente original.
func TestRequisicaoPOSTAssinaEEnvia(t *testing.T) {
	receivedBody := make(chan map[string]any, 1)
	receivedHeaders := make(chan http.Header, 1)

	tribunal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		receivedBody <- body
		receivedHeaders <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer tribunal.Close()

	fs := &fakeSigner{sig: "QUJD", chain: "REVG"}
	srv := pjeoffice.NewServer(fs, "0", "127.0.0.1")

	tarefa := map[string]any{
		"mensagem":            "desafio",
		"enviarPara":          "/cb",
		"token":               "uuid-1",
		"algoritmoAssinatura": "SHA256withRSA",
	}
	tarefaJSON, _ := json.Marshal(tarefa)

	envelope := map[string]any{
		"servidor": tribunal.URL,
		"versao":   "2.5.16",
		"sessao":   "JSESSIONID=abc123",
		"tarefa":   string(tarefaJSON),
	}
	envelopeJSON, _ := json.Marshal(envelope)

	req := httptest.NewRequest(http.MethodPost, "/pjeOffice/requisicao/", bytes.NewReader(envelopeJSON))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	// Cliente deve receber 200 + exatamente os bytes de gifOK
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /requisicao/: want 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "image/gif") {
		t.Fatalf("POST /requisicao/: want image/gif content-type, got %q", ct)
	}
	if got, want := rr.Body.Bytes(), pjeoffice.GifOK(); !bytes.Equal(got, want) {
		t.Fatalf("POST /requisicao/: body bytes mismatch: got %x, want %x", got, want)
	}

	// Login deve ter sido chamado
	if !fs.loginCalled {
		t.Fatal("POST /requisicao/: Login() was not called on the signer")
	}

	// Tribunal deve ter recebido o body correto
	body := <-receivedBody
	if body["assinatura"] != "QUJD" {
		t.Fatalf("tribunal: want assinatura=QUJD, got %v", body["assinatura"])
	}
	if body["certChain"] != "REVG" {
		t.Fatalf("tribunal: want certChain=REVG, got %v", body["certChain"])
	}
	if body["uuid"] != "uuid-1" {
		t.Fatalf("tribunal: want uuid=uuid-1, got %v", body["uuid"])
	}
	if body["mensagem"] != "desafio" {
		t.Fatalf("tribunal: want mensagem=desafio, got %v", body["mensagem"])
	}

	// Headers do tribunal devem incluir versao e Cookie
	hdrs := <-receivedHeaders
	if hdrs.Get("Versao") != "2.5.16" {
		t.Fatalf("tribunal: want versao header=2.5.16, got %q", hdrs.Get("Versao"))
	}
	if !strings.Contains(hdrs.Get("Cookie"), "JSESSIONID=abc123") {
		t.Fatalf("tribunal: want Cookie to contain JSESSIONID=abc123, got %q", hdrs.Get("Cookie"))
	}
}

// TestRequisicaoPOSTSignerError verifica que se o signer falhar, o servidor
// devolve 200 + exatamente os bytes de gifErr (comportamento fiel ao 1.0 Python:
// nunca propaga 5xx ao browser).
// B-1: a asercao discrimina gifErr de gifOK — ambos tem 43 bytes mas conteudo diferente.
func TestRequisicaoPOSTSignerError(t *testing.T) {
	fs := &fakeSigner{signErr: io.ErrUnexpectedEOF}
	srv := pjeoffice.NewServer(fs, "0", "127.0.0.1")

	tarefa := map[string]any{
		"mensagem":            "desafio",
		"enviarPara":          "/cb",
		"token":               "t1",
		"algoritmoAssinatura": "SHA256withRSA",
	}
	tarefaJSON, _ := json.Marshal(tarefa)

	envelope := map[string]any{
		"servidor": "http://localhost:9",
		"versao":   "2.5.16",
		"sessao":   "",
		"tarefa":   string(tarefaJSON),
	}
	envelopeJSON, _ := json.Marshal(envelope)

	req := httptest.NewRequest(http.MethodPost, "/pjeOffice/requisicao/", bytes.NewReader(envelopeJSON))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("signer error: want 200, got %d", rr.Code)
	}
	// Deve ser exatamente gifErr, nao gifOK (ambos tem 43 bytes, conteudo diferente).
	if got, want := rr.Body.Bytes(), pjeoffice.GifErr(); !bytes.Equal(got, want) {
		t.Fatalf("signer error: want gifErr bytes %x, got %x", want, got)
	}
}

// TestRequisicaoGETAssinaEEnvia verifica o fluxo GET com query param ?r= (compatibilidade 1.0).
func TestRequisicaoGETAssinaEEnvia(t *testing.T) {
	receivedBody := make(chan map[string]any, 1)

	tribunal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		receivedBody <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer tribunal.Close()

	fs := &fakeSigner{sig: "U0lH", chain: "Q0VSVA=="}
	srv := pjeoffice.NewServer(fs, "0", "127.0.0.1")

	tarefa := map[string]any{
		"mensagem":            "hello",
		"enviarPara":          "/sign",
		"token":               "tok-get",
		"algoritmoAssinatura": "MD5withRSA",
	}
	tarefaJSON, _ := json.Marshal(tarefa)

	envelope := map[string]any{
		"servidor": tribunal.URL,
		"versao":   "2.5.16",
		"sessao":   "",
		"tarefa":   string(tarefaJSON),
	}
	envelopeJSON, _ := json.Marshal(envelope)

	// Simula o que o browser faz: envia como query string URL-encoded
	reqURL := "/pjeOffice/requisicao/?r=" + urlEncodeJSON(envelopeJSON)

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /requisicao/: want 200, got %d", rr.Code)
	}

	body := <-receivedBody
	if body["uuid"] != "tok-get" {
		t.Fatalf("GET: want uuid=tok-get, got %v", body["uuid"])
	}
	if body["assinatura"] != "U0lH" {
		t.Fatalf("GET: want assinatura=U0lH, got %v", body["assinatura"])
	}
}

// TestRequisicaoPOSTSSRFSchemeRejected verifica que URLs com scheme nao-HTTP
// (file://, gopher://, etc.) sao rejeitadas antes de qualquer conexao de saida,
// e o handler retorna 200 + gifErr ao cliente. B-2 (SSRF guard).
func TestRequisicaoPOSTSSRFSchemeRejected(t *testing.T) {
	fs := &fakeSigner{sig: "QUJD", chain: "REVG"}
	srv := pjeoffice.NewServer(fs, "0", "127.0.0.1")

	tarefa := map[string]any{
		"mensagem":            "desafio",
		"enviarPara":          "/etc/passwd",
		"token":               "t1",
		"algoritmoAssinatura": "SHA256withRSA",
	}
	tarefaJSON, _ := json.Marshal(tarefa)

	for _, badScheme := range []string{"file://", "gopher://host", "ftp://host"} {
		envelope := map[string]any{
			"servidor": badScheme,
			"versao":   "2.5.16",
			"sessao":   "",
			"tarefa":   string(tarefaJSON),
		}
		envelopeJSON, _ := json.Marshal(envelope)

		req := httptest.NewRequest(http.MethodPost, "/pjeOffice/requisicao/", bytes.NewReader(envelopeJSON))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("SSRF %q: want 200, got %d", badScheme, rr.Code)
		}
		if got, want := rr.Body.Bytes(), pjeoffice.GifErr(); !bytes.Equal(got, want) {
			t.Fatalf("SSRF %q: want gifErr bytes, got %x", badScheme, got)
		}
	}
}

// TestRequisicaoPOSTTribunalFails verifica que quando o tribunal retorna 500,
// o handler devolve 200 + exatamente os bytes de gifErr ao cliente.
// B-8: cobre o caminho de falha do POST remoto distinguindo gifErr de gifOK.
func TestRequisicaoPOSTTribunalFails(t *testing.T) {
	tribunal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer tribunal.Close()

	fs := &fakeSigner{sig: "QUJD", chain: "REVG"}
	srv := pjeoffice.NewServer(fs, "0", "127.0.0.1")

	tarefa := map[string]any{
		"mensagem":            "desafio",
		"enviarPara":          "/cb",
		"token":               "t1",
		"algoritmoAssinatura": "SHA256withRSA",
	}
	tarefaJSON, _ := json.Marshal(tarefa)

	envelope := map[string]any{
		"servidor": tribunal.URL,
		"versao":   "2.5.16",
		"sessao":   "",
		"tarefa":   string(tarefaJSON),
	}
	envelopeJSON, _ := json.Marshal(envelope)

	req := httptest.NewRequest(http.MethodPost, "/pjeOffice/requisicao/", bytes.NewReader(envelopeJSON))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("tribunal 500: want 200 from pjeoffice handler, got %d", rr.Code)
	}
	// O handler nao deve propagar 5xx ao browser; deve retornar gifErr discriminado de gifOK.
	if got, want := rr.Body.Bytes(), pjeoffice.GifErr(); !bytes.Equal(got, want) {
		t.Fatalf("tribunal 500: want gifErr bytes %x, got %x", want, got)
	}
}

// urlEncodeJSON encodes JSON bytes to URL percent-encoding (like Python's quote_plus).
func urlEncodeJSON(data []byte) string {
	var b strings.Builder
	for _, c := range data {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			b.WriteByte('%')
			b.WriteByte("0123456789ABCDEF"[c>>4])
			b.WriteByte("0123456789ABCDEF"[c&0xf])
		}
	}
	return b.String()
}
