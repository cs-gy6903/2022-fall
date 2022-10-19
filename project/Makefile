SHELL=bash -e -o pipefail
X509=openssl x509 -text -noout

# "unit-test framework" ;D
all: default

.PHONY: default
default:
	echo | openssl s_client \
		-tls1_3 \
		-showcerts \
		-build_chain \
		-CAfile ./nginx/certs/root.pem \
		-verify_hostname nyu.edu \
		localhost:8443 \
		| tee $@ \
		| $(X509)
	@grep '(ok)' $@
	@rm $@
