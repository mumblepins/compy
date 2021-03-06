package transcoder

import (
	"github.com/mumblepins/compy/proxy"
	"github.com/tdewolff/minify"
	"github.com/tdewolff/minify/css"
	"github.com/tdewolff/minify/html"
	"github.com/tdewolff/minify/js"
	"net/http"
	"regexp"
	"github.com/tdewolff/minify/json"
	"github.com/tdewolff/minify/xml"
)

type Minifier struct {
	m *minify.M
}

func NewMinifier() *Minifier {
	m := minify.New()
	m.AddFunc("text/html", html.Minify)
	m.AddFunc("text/css", css.Minify)
	m.AddFunc("text/javascript", js.Minify)
	m.AddFunc("application/javascript", js.Minify)
	//m.AddFunc("application/x-javascript", js.Minify)

	m.AddFuncRegexp(regexp.MustCompile("[/+]json$"), json.Minify)

	m.AddFuncRegexp(regexp.MustCompile("[/+]xml$"), xml.Minify)
	return &Minifier{
		m: m,
	}
}

func (t *Minifier) Transcode(w *proxy.ResponseWriter, r *proxy.ResponseReader, headers http.Header) error {
	return t.m.Minify(r.ContentType(), w, r)
}
