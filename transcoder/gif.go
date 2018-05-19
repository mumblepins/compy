package transcoder

import (
	"github.com/mumblepins/compy/proxy"
	"net/http"
	"image/gif"
	"bytes"
	"io"
	"os/exec"
	"io/ioutil"
	"path/filepath"
	"syscall"
	"os"
	"bufio"
	"sync"
	"github.com/juju/errors"
)

type Gif struct{}

func (t *Gif) Transcode(w *proxy.ResponseWriter, r *proxy.ResponseReader, headers http.Header) error {

	if SupportsWebP(headers) {

		tmpDir, _ := ioutil.TempDir("", "named-pipes")
		defer os.RemoveAll(tmpDir)
		// Create named pipe
		namedPipe := filepath.Join(tmpDir, "gif_input")
		syscall.Mkfifo(namedPipe, 0600)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			cmd := exec.Command("gif2webp", "-lossy", "-q", "30", "-m", "2",
				//"-min_size",
				namedPipe,
				"-o", "-")
			cmd.Stdout = w
			//start := time.Now()
			err := cmd.Run()
			//log.Println(time.Since(start))
			if err != nil {
				//log.Warn(errors.Details(err))
			}

		}()
		go func() {
			defer wg.Done()
			pipe, _ := os.OpenFile(namedPipe, os.O_RDWR, 0600)
			bufread := bufio.NewReader(r)
			bufread.WriteTo(pipe)
		}()
		wg.Wait()
	} else {
		var buf bytes.Buffer
		tRead := io.TeeReader(r, &buf)
		img, err := gif.DecodeAll(tRead)
		if err != nil {
			return errors.Trace(err)
		}

		if len(img.Image) == 1 {
			buf.WriteTo(w)
		} else {
			if err = gif.Encode(w, img.Image[0], nil); err != nil {
				return errors.Trace(err)
			}
		}

	}
	return nil
}
