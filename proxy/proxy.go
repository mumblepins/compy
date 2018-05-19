package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"github.com/juju/errors"
	"strconv"
)

type Proxy struct {
	transcoders map[string]Transcoder
	ml          *mitmListener
	ReadCount   uint64
	WriteCount  uint64
	user        string
	pass        string
	host        string
	cert        string
	caPath      string
}

type Transcoder interface {
	Transcode(*ResponseWriter, *ResponseReader, http.Header) error
}

func New(host string, cert string) *Proxy {
	p := &Proxy{
		transcoders: make(map[string]Transcoder),
		ml:          nil,
		host:        host,
		cert:        cert,
	}
	return p
}

func (p *Proxy) EnableMitm(ca, key string) error {
	cf, err := newCertFaker(ca, key)
	if err != nil {
		return err
	}
	p.caPath = ca

	var config *tls.Config
	if p.cert != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return errors.Trace(err)
		}
		pem, err := ioutil.ReadFile(p.cert)
		if err != nil {
			return errors.Trace(err)
		}
		ok := roots.AppendCertsFromPEM([]byte(pem))
		if !ok {
			return errors.New("failed to parse root certificate")
		}
		config = &tls.Config{RootCAs: roots}
	}
	p.ml = newMitmListener(cf, config)
	go http.Serve(p.ml, p)
	return nil
}

func (p *Proxy) SetAuthentication(user, pass string) {
	p.user = user
	p.pass = pass
}

func (p *Proxy) AddTranscoder(contentType string, transcoder Transcoder) {
	p.transcoders[contentType] = transcoder
}

func (p *Proxy) Start(host string) error {
	return http.ListenAndServe(host, p)
}

func (p *Proxy) StartTLS(host, cert, key string) error {
	return http.ListenAndServeTLS(host, cert, key, p)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Debugf("serving request: %s", r.URL)
	if err := p.handle(w, r); err != nil {
		log.Warnf("%s while serving request: %s", errors.Details(err), r.URL)
	}
}

func (p *Proxy) checkHttpBasicAuth(auth string) bool {
	prefix := "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}
	values := strings.SplitN(string(decoded), ":", 2)
	if len(values) != 2 || values[0] != p.user || values[1] != p.pass {
		return false
	}
	return true
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) error {
	// TODO: only HTTPS?
	if p.user != "" {
		if !p.checkHttpBasicAuth(r.Header.Get("Proxy-Authorization")) {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Compy\"")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return nil
		}
	}

	if r.Method == "CONNECT" {
		return p.handleConnect(w, r)
	}

	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if hostname, err := os.Hostname(); host == p.host || (err == nil && host == hostname+p.host) {
		return p.handleLocalRequest(w, r)
	}

	resp, err := forward(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return errors.Annotate(err, "error forwarding request")
	}
	defer resp.Body.Close()
	rw := newResponseWriter(w)
	rr := newResponseReader(resp)
	err = p.proxyResponse(rw, rr, r.Header)
	read := rr.counter.Count()
	written := rw.rw.Count()
	log.Infof("transcoded: %d -> %d (%3.1f%%)", read, written, float64(written)/float64(read)*100)
	atomic.AddUint64(&p.ReadCount, read)
	atomic.AddUint64(&p.WriteCount, written)
	return errors.Trace(err)
}

func (p *Proxy) handleLocalRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" && (r.URL.Path == "" || r.URL.Path == "/") {
		w.Header().Set("Content-Type", "text/html")
		read := atomic.LoadUint64(&p.ReadCount)
		written := atomic.LoadUint64(&p.WriteCount)
		io.WriteString(w, fmt.Sprintf(`<html>
<head>
<title>compy</title>
</head>
<body>
<h1>compy</h1>
<ul>
<li>total transcoded: %d -> %d (%3.1f%%)</li>
<li><a href="/cacert">CA cert</a></li>
<li><a href="https://github.com/mumblepins/compy">GitHub</a></li>
</ul>
</body>
</html>`, read, written, float64(written)/float64(read)*100))
		return nil
	} else if r.Method == "GET" && r.URL.Path == "/cacert" {
		if p.caPath == "" {
			http.NotFound(w, r)
			return nil
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		http.ServeFile(w, r, p.caPath)
		return nil
	} else {
		w.WriteHeader(http.StatusNotImplemented)
		return nil
	}
}

func forward(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme == "" {
		if r.TLS != nil && r.TLS.ServerName == r.Host {
			r.URL.Scheme = "https"
		} else {
			r.URL.Scheme = "http"
		}
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	r.RequestURI = ""
	return http.DefaultTransport.RoundTrip(r)
}

func (p *Proxy) proxyResponse(w *ResponseWriter, r *ResponseReader, headers http.Header) error {
	w.takeHeaders(r)
	cLength, err := strconv.Atoi(r.Header().Get("Content-Length"))
	if err != nil || cLength < 20 {
		return errors.Trace(w.ReadFrom(r))
	}
	transcoder, found := p.transcoders[r.ContentType()]
	if !found {
		return errors.Trace(w.ReadFrom(r))
	}
	w.setChunked()
	w.Header().Del("Strict-Transport-Security")

	r.Header().Del("Strict-Transport-Security")
	if err := transcoder.Transcode(w, r, headers); err != nil {
		return errors.Annotate(err, "transcoding error")
	}
	return nil
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) error {
	if p.ml == nil {
		return errors.Errorf("CONNECT received but mitm is not enabled")
	}
	w.WriteHeader(http.StatusOK)
	var conn net.Conn
	if h, ok := w.(http.Hijacker); ok {
		conn, _, _ = h.Hijack()
	} else {
		fw := w.(FlushWriter)
		fw.Flush()
		mconn := newMitmConn(fw, r.Body, r.RemoteAddr)
		conn = mconn
		defer func() {
			<-mconn.closed
		}()
	}
	sconn, err := p.ml.Serve(conn, r.Host)
	if err != nil {
		conn.Close()
		return errors.Trace(err)
	}
	sconn.Close() // TODO: reuse this connection for https requests
	return nil
}
