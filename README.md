# acme-client-route53

acme-client-route53 is a simple tool to obtain X.509 certificates using [RFC8555 ACME](https://datatracker.ietf.org/doc/html/rfc8555) [DNS Challenge](https://datatracker.ietf.org/doc/html/rfc8555#section-8.4).
It is intended for periodic execution on AWS Lambda and validating the domain names using AWS Route53 or Lightsail DNS.
