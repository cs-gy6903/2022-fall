SHELL=bash -e -o pipefail
X509=openssl x509 -text -noout

ROOT=./nginx/certs/root.pem

# "unit-test framework" ;D
all: default  sni

.PHONY: default
default:
	echo | openssl s_client \
		-tls1_3 \
		-showcerts \
		-build_chain \
		-CAfile $(ROOT) \
		-noservername \
		-verify_hostname cs-gy6903.nyu.edu \
		localhost:8443 \
		| tee $@ \
		| $(X509)
	@grep '(ok)' $@
	@rm $@
	curl https://localhost:8443 \
		--silent \
		--insecure \
		| grep 'no sni'

.PHONY: sni
sni:
	echo | openssl s_client \
		-tls1_3 \
		-showcerts \
		-build_chain \
		-CAfile $(ROOT) \
		-servername cs-gy6903.nyu.edu \
		-verify_hostname cs-gy6903.nyu.edu \
		localhost:8443 \
		| tee $@ \
		| $(X509)
	@grep '(ok)' $@
	@rm $@
	curl https://cs-gy6903.nyu.edu:8443 \
		--silent \
		--insecure \
		--resolve cs-gy6903.nyu.edu:8443:127.0.0.1 \
		| grep 'with sni'
