package main

import (
	"flag"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"sync/atomic"

	"github.com/mumblepins/compy/proxy"
	tc "github.com/mumblepins/compy/transcoder"
	"time"
)

var (
	host  = flag.String("host", ":9999", "<host:port>")
	cert  = flag.String("cert", "", "proxy cert path")
	key   = flag.String("key", "", "proxy cert key path")
	ca    = flag.String("ca", "", "CA path")
	caKey = flag.String("cakey", "", "CA key path")
	user  = flag.String("user", "", "proxy user name")
	pass  = flag.String("pass", "", "proxy password")

	loglevel = flag.Int("loglevel", 3, "Log level (0-5, higher is more debugging, default:3)")

	brotli = flag.Int("brotli", 6, "Brotli compression level (0-11)")
	jpeg   = flag.Int("jpeg", 50, "jpeg quality (1-100, 0 to disable)")
	gif    = flag.Bool("gif", true, "transcode gifs into static images")
	gzip   = flag.Int("gzip", 6, "gzip compression level (0-9)")
	png    = flag.Bool("png", true, "transcode png")
	minify = flag.Bool("minify", false, "minify css/html/js - WARNING: tends to break the web")
)

func main() {
	flag.Parse()
	if *loglevel > 5 {
		*loglevel = 5
	} else if *loglevel < 0 {
		*loglevel = 0
	}
	log.SetLevel(log.Level(*loglevel))
	p := proxy.New(*host, *cert)

	if (*ca == "") != (*caKey == "") {
		log.Error("must specify both CA certificate and key")
	}

	if (*cert == "") != (*key == "") {
		log.Error("must specify both certificate and key")
	}

	if *ca != "" {
		if err := p.EnableMitm(*ca, *caKey); err != nil {
			log.Warn("not using mitm:", err)
		}
	}
	log.Infof("Using MITM with CA: %s and Key: %s", *ca, *caKey)
	// TODO: require cert and key?
	if (*user == "") != (*pass == "") {
		log.Error("must specify both user and pass")
	} else {
		p.SetAuthentication(*user, *pass)
	}

	if *jpeg != 0 {
		p.AddTranscoder("image/jpeg", tc.NewJpeg(*jpeg))
	}
	if *gif {
		p.AddTranscoder("image/gif", &tc.Gif{})
	}
	if *png {
		p.AddTranscoder("image/png", &tc.Png{})
	}

	var ttc proxy.Transcoder
	if *minify {
		ttc = &tc.Zip{tc.NewMinifier(), *brotli, *gzip, false}
	} else {
		ttc = &tc.Zip{&tc.Identity{}, *brotli, *gzip, true}
	}

	p.AddTranscoder("text/css", ttc)
	p.AddTranscoder("text/html", ttc)
	p.AddTranscoder("text/javascript", ttc)
	p.AddTranscoder("application/javascript", ttc)
	p.AddTranscoder("application/x-javascript", ttc)

	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			read := atomic.LoadUint64(&p.ReadCount)
			written := atomic.LoadUint64(&p.WriteCount)
			log.Warnf("Total transcoded: %d -> %d (%3.1f%%)",
				read, written, float64(written)/float64(read)*100)
		}
	}()
	defer ticker.Stop()

	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			read := atomic.LoadUint64(&p.ReadCount)
			written := atomic.LoadUint64(&p.WriteCount)
			log.Warnf("compy exiting, total transcoded: %d -> %d (%3.1f%%)",
				read, written, float64(written)/float64(read)*100)
			os.Exit(0)
		}
	}()

	log.Warnf("compy listening on %s", *host)

	var err error
	if *cert != "" {
		err = p.StartTLS(*host, *cert, *key)
	} else {
		err = p.Start(*host)
	}
	log.Fatal(err)
}
