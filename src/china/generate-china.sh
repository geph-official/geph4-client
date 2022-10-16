#lang racket
(require net/url)

(define seen (mutable-set))

(define (generate-list (name "geolocation-cn"))
  (define url (string->url
               (format "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/~a" name)))
  (for ([line (in-lines (get-pure-port url))])
    (match (string-trim line)
      [(or "" (regexp #rx"^#")) (void)]
      [(regexp #rx"^include:")
       (generate-list (car (string-split (substring line 8))))]
      [(regexp #rx":") (void)]
      [x
       (define element (car (string-split x)))
       (unless (set-member? seen element)
         (set-add! seen element)
         (printf "~a\n" (car (string-split x))))])))

(define (process-dnsmasq-line line)
  (second (string-split line "/")))

(define (dump-dnsmasq location)
  (define url (string->url location))
  (for ([line (in-lines (get-pure-port url))])
    (printf "~a\n" (process-dnsmasq-line line))))

(dump-dnsmasq "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf")
