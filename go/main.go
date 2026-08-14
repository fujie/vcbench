// linux-bench Go engine — VCフォーマット別 署名/検証ベンチマーク
//
// 計測方式:
//   - time.Now()（モノトニック、ns精度）で各イテレーションを個別記録
//   - ウォームアップ後に本計測
//   - 統計計算は行わず生タイミング(ns)を出力（統計は ../aggregate.mjs が一元計算）
//
// ビルド: go build -o vc-bench .
// 使い方: ./vc-bench -format sdjwt|jsonld|jsonld-jcs|mdoc|all [-n 2000] [-warmup 50] [-out results.json]
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	cborlib "github.com/fxamacker/cbor/v2"
	jsonldgo "github.com/piprate/json-gold/ld"
)

var (
	formatFlag = flag.String("format", "all", "sdjwt|jsonld|jsonld-jcs|mdoc|all")
	nFlag      = flag.Int("n", 2000, "iterations per benchmark")
	warmupFlag = flag.Int("warmup", 50, "warmup iterations")
	outFlag    = flag.String("out", "", "output JSON file (default: stdout)")
)

type BenchRaw struct {
	N        int     `json:"n"`
	Warmup   int     `json:"warmup"`
	Timings  []int64 `json:"timings_ns"`
}

var benches = map[string]BenchRaw{}

func bench(key string, n int, fn func()) {
	for i := 0; i < *warmupFlag; i++ {
		fn()
	}
	timings := make([]int64, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		fn()
		timings[i] = time.Since(start).Nanoseconds()
	}
	benches[key] = BenchRaw{N: n, Warmup: *warmupFlag, Timings: timings}
	fmt.Fprintf(os.Stderr, "  %s: done (n=%d)\n", key, n)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

const credNS = "https://www.w3.org/2018/credentials#"
const rdfType = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"

// 共通クレデンシャル（論文4.3.1と同一ペイロード）
var vcDoc = map[string]interface{}{
	"@context": []interface{}{map[string]interface{}{
		"@version":             1.1,
		"type":                 "@type",
		"id":                   "@id",
		"VerifiableCredential": credNS + "VerifiableCredential",
		"issuer":               map[string]interface{}{"@id": credNS + "issuer", "@type": "@id"},
		"issuanceDate":         map[string]interface{}{"@id": credNS + "issuanceDate", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
		"credentialSubject":    credNS + "credentialSubject",
		"name":                 "http://schema.org/name",
	}},
	"type":         "VerifiableCredential",
	"issuer":       "https://example.com",
	"issuanceDate": "2024-01-01T00:00:00Z",
	"credentialSubject": map[string]interface{}{
		"id": "did:example:1", "name": "Taro Yamada",
	},
}

// ── SD-JWT VC (Ed25519, crypto/ed25519) ──────────────────────────
func runSdJwt() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "crv": "Ed25519"})
	payload, _ := json.Marshal(map[string]string{
		"iss": "https://issuer.example.com", "vct": "identity", "sub": "did:example:holder"})
	sigInput := []byte(b64url(header) + "." + b64url(payload))

	bench("sdjwt/stdlib/sign", *nFlag, func() {
		sig := ed25519.Sign(priv, sigInput)
		_ = string(sigInput) + "." + b64url(sig)
	})

	token := string(sigInput) + "." + b64url(ed25519.Sign(priv, sigInput))
	bench("sdjwt/stdlib/verify", *nFlag, func() {
		parts := strings.Split(token, ".")
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig)
	})
}

// ── JSON-LD VC (URDNA2015, json-gold) ────────────────────────────
func normalizeJsonLd(proc *jsonldgo.JsonLdProcessor, opts *jsonldgo.JsonLdOptions) string {
	norm, err := proc.Normalize(vcDoc, opts)
	if err != nil {
		panic(err)
	}
	return norm.(string)
}

func runJsonLd() {
	proc := jsonldgo.NewJsonLdProcessor()
	opts := jsonldgo.NewJsonLdOptions("")
	opts.Algorithm = jsonldgo.AlgorithmURDNA2015
	opts.Format = "application/n-quads"

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	bench("jsonld/json-gold/sign", *nFlag, func() {
		norm := normalizeJsonLd(proc, opts)
		h := sha256.Sum256([]byte(norm))
		ed25519.Sign(priv, h[:])
	})

	norm0 := normalizeJsonLd(proc, opts)
	h0 := sha256.Sum256([]byte(norm0))
	sig0 := ed25519.Sign(priv, h0[:])
	bench("jsonld/json-gold/verify", *nFlag, func() {
		norm := normalizeJsonLd(proc, opts)
		h := sha256.Sum256([]byte(norm))
		ed25519.Verify(pub, h[:], sig0)
	})

	bench("jsonld/json-gold/normalize-only", *nFlag, func() {
		normalizeJsonLd(proc, opts)
	})

	// noLib: インラインN-Quads
	inlineNorm := func() []byte {
		s, sub := "_:c14n0", "<did:example:1>"
		quads := []string{
			sub + " <http://schema.org/name> \"Taro Yamada\" .",
			s + " <" + rdfType + "> <" + credNS + "VerifiableCredential> .",
			s + " <" + credNS + "credentialSubject> " + sub + " .",
			s + " <" + credNS + "issuanceDate> \"2024-01-01T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .",
			s + " <" + credNS + "issuer> <https://example.com> .",
		}
		sort.Strings(quads)
		return []byte(strings.Join(quads, "\n") + "\n")
	}
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	bench("jsonld/nolib/sign", *nFlag, func() {
		h := sha256.Sum256(inlineNorm())
		ed25519.Sign(priv2, h[:])
	})
	h1 := sha256.Sum256(inlineNorm())
	sig1 := ed25519.Sign(priv2, h1[:])
	bench("jsonld/nolib/verify", *nFlag, func() {
		h := sha256.Sum256(inlineNorm())
		ed25519.Verify(pub2, h[:], sig1)
	})
}

// ── JSON-LD VC (JCS / RFC 8785) ──────────────────────────────────
// encoding/json の Marshal は map のキーをソートするため、
// 本ベンチのデータ（ASCII・単純型）では JCS 相当の正準形が得られる。
func runJcs() {
	doc := map[string]interface{}{
		"@context":          map[string]interface{}{"@version": 1.1, "id": "@id", "type": "@type"},
		"type":              "VerifiableCredential",
		"issuer":            "https://example.com",
		"issuanceDate":      "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{"id": "did:example:1", "name": "Taro Yamada"},
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	canonical := func() []byte {
		b, _ := json.Marshal(doc)
		return b
	}
	bench("jsonld-jcs/nolib/sign", *nFlag, func() {
		h := sha256.Sum256(canonical())
		ed25519.Sign(priv, h[:])
	})
	h0 := sha256.Sum256(canonical())
	sig0 := ed25519.Sign(priv, h0[:])
	bench("jsonld-jcs/nolib/verify", *nFlag, func() {
		h := sha256.Sum256(canonical())
		ed25519.Verify(pub, h[:], sig0)
	})
}

// ── mdoc (CBOR/COSE + ECDSA P-256) ───────────────────────────────
var mdocFields = [][2]string{
	{"family_name", "Yamada"}, {"given_name", "Taro"}, {"birth_date", "1990-01-01"},
	{"issue_date", "2024-01-01"}, {"expiry_date", "2029-01-01"},
	{"issuing_country", "JP"}, {"document_number", "JP-12345678"},
}

func runMdoc() {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &priv.PublicKey

	buildSigStruct := func() []byte {
		digestMap := map[int][]byte{}
		for i, kv := range mdocFields {
			item, _ := cborlib.Marshal(map[string]interface{}{
				"digestID": i, "elementIdentifier": kv[0], "elementValue": kv[1]})
			h := sha256.Sum256(item)
			digestMap[i] = h[:]
		}
		protHdr, _ := cborlib.Marshal(map[int]int{1: -7})
		mso, _ := cborlib.Marshal(map[string]interface{}{
			"docType": "org.iso.18013.5.1.mDL", "valueDigests": digestMap})
		sigStruct, _ := cborlib.Marshal([]interface{}{"Signature1", protHdr, []byte{}, mso})
		return sigStruct
	}

	bench("mdoc/fxamacker-cbor/sign", *nFlag, func() {
		ss := buildSigStruct()
		h := sha256.Sum256(ss)
		// COSE は raw r||s。SignASN1 の代わりに ecdsa.Sign で r,s を取得
		r, s, _ := ecdsa.Sign(rand.Reader, priv, h[:])
		raw := make([]byte, 64)
		r.FillBytes(raw[:32])
		s.FillBytes(raw[32:])
		_ = raw
	})

	ss0 := buildSigStruct()
	h0 := sha256.Sum256(ss0)
	r0, s0, _ := ecdsa.Sign(rand.Reader, priv, h0[:])
	bench("mdoc/fxamacker-cbor/verify", *nFlag, func() {
		h := sha256.Sum256(ss0)
		ecdsa.Verify(pub, h[:], r0, s0)
	})
}

// ── main ─────────────────────────────────────────────────────────
func main() {
	flag.Parse()
	runners := map[string]func(){
		"sdjwt":      runSdJwt,
		"jsonld":     runJsonLd,
		"jsonld-jcs": runJcs,
		"mdoc":       runMdoc,
	}
	order := []string{"sdjwt", "jsonld", "jsonld-jcs", "mdoc"}

	var targets []string
	if *formatFlag == "all" {
		targets = order
	} else {
		if _, ok := runners[*formatFlag]; !ok {
			fmt.Fprintf(os.Stderr, "unknown format: %s\n", *formatFlag)
			os.Exit(1)
		}
		targets = []string{*formatFlag}
	}
	for _, f := range targets {
		fmt.Fprintf(os.Stderr, "[go] format=%s\n", f)
		runners[f]()
	}

	result := map[string]interface{}{
		"lang":   "go",
		"format": *formatFlag,
		"n":      *nFlag,
		"warmup": *warmupFlag,
		"env": map[string]interface{}{
			"go":       runtime.Version(),
			"platform": runtime.GOOS + " " + runtime.GOARCH,
			"cores":    runtime.NumCPU(),
			"libraries": map[string]string{
				"github.com/piprate/json-gold": "see go.sum",
				"github.com/fxamacker/cbor/v2": "see go.sum",
			},
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
		"benches": benches,
	}
	data, _ := json.Marshal(result)
	if *outFlag != "" {
		if err := os.WriteFile(*outFlag, data, 0o644); err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *outFlag)
	} else {
		fmt.Println(string(data))
	}
}
