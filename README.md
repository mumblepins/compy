Compy
=====

Compy is an HTTP/HTTPS forward proxy with content compression/transcoding capabilities.  
One use case is to reduce bandwidth usage when browsing on limited mobile broadband connection.


Features
--------

- HTTPS proxy (encrypted connection between client and proxy)
- man in the middle support (compress HTTPS traffic)
- HTTP2 support (over TLS)
- Brotli and gzip compression
- transcode animated GIFs to static images
- transcode JPEG images to desired quality using libjpeg
- transcode PNG and JPEG images to WebP
- HTML/CSS/JavaScript minification


Installation
------------

compy needs a few libraries to compile.
On Ubuntu, run `apt-get install -y libjpeg8 openssl ssl-cert`.
On macOS, run `brew install jpeg`.  Then compile via:

```ShellSession
$ go get github.com/mumblepins/compy
$ cd go/src/github.com/mumblepins/compy/
$ go install
```

go will generate the binary at `go/bin/compy`.

### HTTPS
To use the proxy over HTTPS, you will need a certificate for your host. If you don't already have one, you can get one for [free](https://letsencrypt.org/) or you can generate a self-signed cert by running:  
```
openssl req -x509 -newkey rsa:2048 -nodes -keyout cert.key -out cert.crt -days 3650 -subj '/CN=<your-domain>'
```
then visit the proxy URL and confirm that you trust your own certificate

To connect to the proxy over TLS, you will need to supply a PAC (proxy auto-config) file to the browser, as most of them do not expose this option to the UI directly. Example:
```javascript
function FindProxyForURL(url, host) {
   if (url.substring(0, 5) == 'http:' || url.substring(0, 6) == 'https:') {
      return "HTTPS <your-domain>:9999";
   }
   return "DIRECT";
}
```

This tells the browser to fetch HTTP and HTTPS URLs via the HTTPS proxy and for all other schemas, e.g., WebSocket, connect directly.
Set the path to this file in the browser UI and you're good to go.

### MitM
To enable man-in-the-middle support, you will need to generate a root cert to sign all the certs generated by the proxy on the fly:  
```
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 -subj '/CN=<your-domain>'
```
and add it to your client (browser) as a trusted certificate authority


Usage
-----

To run a simple http forward proxy:  
```
compy
```

To run it over TLS:
```
compy -cert cert.crt -key cert.key
```

With man in the middle support:  
```
compy -ca ca.crt -cakey ca.key
```

Probably the best option is to run it with both TLS and MitM support, combining the two:
```
compy -cert cert.crt -key cert.key -ca ca.crt -cakey ca.key
```

You can limit access to your proxy via HTTP BASIC authentication:

```
compy -cert cert.crt -key cert.key -user myuser -pass mypass
```

You can also specify the listen port (defaults to 9999):  
```
compy -host :9999
```

For compression, transcoding and minification options, see `compy --help`

Docker Usage
------------

Andrew Gaul publishes unofficial Docker images at
https://hub.docker.com/r/andrewgaul/compy/ .  You can configure via:

```
sudo docker run --name=compy --env CERTIFICATE_DOMAIN=example.com --publish 9999:9999 andrewgaul/compy
```

References
----------

* [Google Flywheel](https://www.usenix.org/conference/nsdi15/technical-sessions/presentation/agababov) - NSDI 2015 paper discussing techniques used by Chrome data saver
* [Mozilla Janus](https://wiki.mozilla.org/Mobile/Janus) - now-defunct experiment similar to compy
* [Ziproxy](https://en.wikipedia.org/wiki/Ziproxy) - older approach similar to compy

Credits
-------

https://github.com/pixiv/go-libjpeg  
https://github.com/tdewolff/minify


License
-------

ISC, see LICENSE
