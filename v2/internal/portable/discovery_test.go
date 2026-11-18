package portable

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"
)

// C23.04: discovery.json покрыт подписью манифеста; узлы проверяются строго.
func TestDiscoveryInPackage(t *testing.T) {
	priv, trust := keys()
	o := fixtureObs(t, id1, "")
	tenant, source := tenantSource(t, o)
	so, err := SignObservation(priv, o)
	if err != nil {
		t.Fatal(err)
	}
	doc := func(hosts string) []byte {
		return []byte(`{"schema_version":{"major":1,"minor":0},"ranges":["10.20.0.0/16"],"excluded":["10.20.5.0/24"],"started_at":"2026-11-18T10:00:00Z","finished_at":"2026-11-18T10:05:00Z","complete":true,"hosts":[` + hosts + `]}`)
	}
	pkg := func(d []byte) []byte {
		var buf bytes.Buffer
		if err := WriteWithDiscovery(&buf, priv, tenant, source, time.Now(), [][]byte{so}, d); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	good := doc(`{"ip":"10.20.1.15","ports":[22],"kind":"linux_ssh","outcome":"collected","observation_id":"` + id1 + `"},
{"ip":"10.20.1.40","ports":[5985],"kind":"windows_winrm","outcome":"no_access","reason":"AUTH_FAILED","profile":"Домен RO"},
{"ip":"10.20.1.77","ports":[],"kind":"unknown","outcome":"no_profile"}`)
	res, err := Import(pkg(good), trust, Known{}, DefaultLimits(), nil)
	if err != nil || res.Discovery == nil || len(res.Discovery.Hosts) != 3 || len(res.Accepted) != 1 {
		t.Fatal("valid discovery", err, res.Discovery)
	}
	for name, hosts := range map[string]string{
		"outside range":        `{"ip":"10.30.1.1","ports":[],"kind":"unknown","outcome":"no_profile"}`,
		"excluded":             `{"ip":"10.20.5.9","ports":[],"kind":"unknown","outcome":"no_profile"}`,
		"duplicate ip":         `{"ip":"10.20.1.1","ports":[],"kind":"unknown","outcome":"no_profile"},{"ip":"10.20.1.1","ports":[],"kind":"unknown","outcome":"skipped"}`,
		"collected without id": `{"ip":"10.20.1.1","ports":[22],"kind":"linux_ssh","outcome":"collected"}`,
		"foreign observation":  `{"ip":"10.20.1.1","ports":[22],"kind":"linux_ssh","outcome":"collected","observation_id":"` + id2 + `"}`,
		"free-text reason":     `{"ip":"10.20.1.1","ports":[22],"kind":"linux_ssh","outcome":"no_access","reason":"password wrong for admin"}`,
		"unknown field":        `{"ip":"10.20.1.1","ports":[],"kind":"unknown","outcome":"skipped","password":"x"}`,
	} {
		if _, err := Import(pkg(doc(hosts)), trust, Known{}, DefaultLimits(), nil); err == nil {
			t.Fatal(name, "must be rejected")
		}
	}
	// подмена discovery.json после подписи — отказ; discovery.json без записи в манифесте — отказ
	tampered := replaceFile(t, pkg(good), "discovery.json", doc(`{"ip":"10.20.1.99","ports":[],"kind":"unknown","outcome":"skipped"}`))
	if _, err := Import(tampered, trust, Known{}, DefaultLimits(), nil); err == nil {
		t.Fatal("tampered discovery accepted")
	}
	extra := replaceFile(t, pkg(nil), "discovery.json", good)
	if _, err := Import(extra, trust, Known{}, DefaultLimits(), nil); err == nil {
		t.Fatal("unlisted discovery accepted")
	}
	if res, err := Import(pkg(nil), trust, Known{}, DefaultLimits(), nil); err != nil || res.Discovery != nil {
		t.Fatal("package without discovery must import as before", err)
	}
}

// replaceFile — копия ZIP с заменой (или добавлением) файла name.
func replaceFile(t *testing.T, data []byte, name string, body []byte) []byte {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		if f.Name == name {
			continue
		}
		r, _ := f.Open()
		var b bytes.Buffer
		_, _ = b.ReadFrom(r)
		w, _ := zw.Create(f.Name)
		_, _ = w.Write(b.Bytes())
	}
	w, _ := zw.Create(name)
	_, _ = w.Write(body)
	_ = zw.Close()
	return buf.Bytes()
}
