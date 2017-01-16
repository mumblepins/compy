Compy
=====

Compy is an HTTP/HTTPS forward proxy with content compression/transcoding capabilities.  
One use case is to reduce bandwidth usage when browsing on limited mobile broadband connection.


Features:
---------

- HTTPS proxy (encrypted connection between client and proxy)
- man in the middle support (compress HTTPS traffic)
- HTTP2 support (over tls)
- gzip compression
- transcode animated gifs to static images
- transcode jpeg images to desired quality using libjpeg
- transcode PNG and JPEG images to WebP
- html/css/js minification


Installation
------------

`go get github.com/barnacs/compy`

### HTTPS
To use the proxy over HTTPS, you will need a certificate for your host. If you don't already have one, you can get one for [free](https://letsencrypt.org/) or you can generate a self-signed cert by running:  
`openssl req -x509 -newkey rsa:2048 -nodes -keyout cert.key -out cert.crt -days 3650 -subj '/CN=<your-domain>'`  
then visit the proxy url and confirm that you trust your own certificate

To connect to the proxy over tls, you will need to supply a PAC (proxy auto-config) file to the browser, as most of them do not expose this option to the UI directly. Example:  
```
function FindProxyForURL(url, host) {
   if (url.substring(0, 5) == 'http:' || url.substring(0, 6) == 'https:') {
      return "HTTPS <your-domain>:9999";
   }
   return "DIRECT";
}

```
This tells the browser to fetch http/https urls via the https proxy and for all other schemas (eg. websocket) connect directly.  
Set the path to this file in the browser UI and you're good to go.

### MitM
To enable man-in-the-middle support, you will need to generate a root cert to sign all the certs generated by the proxy on the fly:  
`openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 -subj '/CN=<your-domain>'`  
and add it to your client (browser) as a trusted certificate authority


Usage
-----

To run a simple http forward proxy:  
`compy`

To run it over tls:  
`compy -cert cert.crt -key cert.key`

With man in the middle support:  
`compy -ca ca.crt -cakey ca.key`

Probably the best option is to run it with both tls and mitm support, combining the two:  
`compy -cert cert.crt -key cert.key -ca ca.crt -cakey ca.key`

You can also specify the listen port (defaults to 9999):  
`compy -host :9999`

For compression, transcoding and minification options, see `compy --help`


Credits
-------

https://github.com/pixiv/go-libjpeg  
https://github.com/tdewolff/minify


License
-------

ISC, see LICENSE
