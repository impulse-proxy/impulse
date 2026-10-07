.PHONY: run build build-impulse clean test test-edge test-transport bench-route-index bench-load-balancing certs certs-selfsigned certs-ca certs-clean certs-verify certs-dir

CERTS_DIR := certs
SAN_CONF := $(CERTS_DIR)/san.conf
CA_CONF := $(CERTS_DIR)/ca.conf

run:
	make build
	./target/release/impulse --config config/config.yaml

build:
	cargo build --release

build-impulse:
	cargo build -p impulse --bin impulse --release

test:
	cargo test --workspace

test-edge:
	cargo test -p impulse-edge

test-transport:
	cargo test -p impulse-transport

bench-route-index:
	cargo bench -p impulse-edge --bench route_index

bench-load-balancing:
	cargo bench -p impulse-lb --bench load_balancing

# Certificate generation targets
certs-dir:
	mkdir -p $(CERTS_DIR)

$(SAN_CONF): | certs-dir
	@if [ ! -f "$(SAN_CONF)" ]; then \
		echo "[req]" > "$(SAN_CONF)"; \
		echo "default_bits = 2048" >> "$(SAN_CONF)"; \
		echo "prompt = no" >> "$(SAN_CONF)"; \
		echo "default_md = sha256" >> "$(SAN_CONF)"; \
		echo "distinguished_name = req_distinguished_name" >> "$(SAN_CONF)"; \
		echo "req_extensions = v3_req" >> "$(SAN_CONF)"; \
		echo "" >> "$(SAN_CONF)"; \
		echo "[req_distinguished_name]" >> "$(SAN_CONF)"; \
		echo "C = US" >> "$(SAN_CONF)"; \
		echo "ST = California" >> "$(SAN_CONF)"; \
		echo "L = San Francisco" >> "$(SAN_CONF)"; \
		echo "O = Impulse Proxy" >> "$(SAN_CONF)"; \
		echo "OU = Development" >> "$(SAN_CONF)"; \
		echo "CN = proxy.impulse.local" >> "$(SAN_CONF)"; \
		echo "" >> "$(SAN_CONF)"; \
		echo "[v3_req]" >> "$(SAN_CONF)"; \
		echo "basicConstraints = critical, CA:FALSE" >> "$(SAN_CONF)"; \
		echo "keyUsage = critical, digitalSignature, keyEncipherment" >> "$(SAN_CONF)"; \
		echo "extendedKeyUsage = serverAuth" >> "$(SAN_CONF)"; \
		echo "subjectAltName = @alt_names" >> "$(SAN_CONF)"; \
		echo "" >> "$(SAN_CONF)"; \
		echo "[v3_leaf]" >> "$(SAN_CONF)"; \
		echo "basicConstraints = critical, CA:FALSE" >> "$(SAN_CONF)"; \
		echo "keyUsage = critical, digitalSignature, keyEncipherment" >> "$(SAN_CONF)"; \
		echo "extendedKeyUsage = serverAuth" >> "$(SAN_CONF)"; \
		echo "subjectKeyIdentifier = hash" >> "$(SAN_CONF)"; \
		echo "authorityKeyIdentifier = keyid,issuer" >> "$(SAN_CONF)"; \
		echo "subjectAltName = @alt_names" >> "$(SAN_CONF)"; \
		echo "" >> "$(SAN_CONF)"; \
		echo "[alt_names]" >> "$(SAN_CONF)"; \
		echo "DNS.1 = localhost" >> "$(SAN_CONF)"; \
		echo "DNS.2 = proxy.impulse.local" >> "$(SAN_CONF)"; \
		echo "IP.1 = 127.0.0.1" >> "$(SAN_CONF)"; \
		echo "IP.2 = ::1" >> "$(SAN_CONF)"; \
		echo "✅ Created default $(SAN_CONF)"; \
	fi

$(CA_CONF): | certs-dir
	@if [ ! -f "$(CA_CONF)" ]; then \
		echo "[req]" > "$(CA_CONF)"; \
		echo "prompt = no" >> "$(CA_CONF)"; \
		echo "default_md = sha256" >> "$(CA_CONF)"; \
		echo "distinguished_name = req_distinguished_name" >> "$(CA_CONF)"; \
		echo "x509_extensions = v3_ca" >> "$(CA_CONF)"; \
		echo "" >> "$(CA_CONF)"; \
		echo "[req_distinguished_name]" >> "$(CA_CONF)"; \
		echo "C = US" >> "$(CA_CONF)"; \
		echo "ST = California" >> "$(CA_CONF)"; \
		echo "L = San Francisco" >> "$(CA_CONF)"; \
		echo "O = Impulse Proxy CA" >> "$(CA_CONF)"; \
		echo "OU = Certificate Authority" >> "$(CA_CONF)"; \
		echo "CN = Impulse Proxy Root CA" >> "$(CA_CONF)"; \
		echo "" >> "$(CA_CONF)"; \
		echo "[v3_ca]" >> "$(CA_CONF)"; \
		echo "basicConstraints = critical, CA:TRUE" >> "$(CA_CONF)"; \
		echo "keyUsage = critical, keyCertSign, cRLSign" >> "$(CA_CONF)"; \
		echo "subjectKeyIdentifier = hash" >> "$(CA_CONF)"; \
		echo "authorityKeyIdentifier = keyid:always,issuer" >> "$(CA_CONF)"; \
		echo "✅ Created default $(CA_CONF)"; \
	fi

certs-selfsigned: $(SAN_CONF)
	@echo "🔐 Generating ECC P-256 private key..."
	openssl ecparam -name prime256v1 -genkey -noout -out certs/proxy-key.pem
	@echo "🔄 Converting to PKCS#8 format for rustls compatibility..."
	openssl pkcs8 -topk8 -nocrypt -in certs/proxy-key.pem -out certs/proxy-key-pkcs8.pem
	@echo "📄 Creating Certificate Signing Request (CSR)..."
	openssl req -new -key certs/proxy-key-pkcs8.pem -out certs/proxy.csr -config certs/san.conf -extensions v3_req
	@echo "🏛️ Creating self-signed certificate..."
	openssl x509 -req -in certs/proxy.csr -signkey certs/proxy-key-pkcs8.pem -out certs/proxy-cert.pem -days 365 -extensions v3_req -extfile certs/san.conf -sha256
	@echo "🔄 Converting to DER format..."
	openssl pkcs8 -in certs/proxy-key-pkcs8.pem -topk8 -nocrypt -outform DER -out certs/proxy-key.der
	openssl x509 -in certs/proxy-cert.pem -outform DER -out certs/proxy-cert.der
	@echo "🔒 Setting secure permissions..."
	chmod 600 certs/proxy-key.pem certs/proxy-key-pkcs8.pem certs/proxy-key.der
	chmod 644 certs/proxy-cert.pem certs/proxy-cert.der
	@echo "✅ Self-signed certificates created successfully!"

certs-ca: $(SAN_CONF) $(CA_CONF)
	@# Existing san.conf files from older versions may contain authorityKeyIdentifier
	@# in v3_req, which breaks CSR generation (CSRs have no issuer yet).
	@if ! grep -q '^\[v3_leaf\]$$' certs/san.conf; then \
		sed -i '/^[[:space:]]*authorityKeyIdentifier[[:space:]]*=.*/d' certs/san.conf; \
		echo "" >> certs/san.conf; \
		echo "[v3_leaf]" >> certs/san.conf; \
		echo "basicConstraints = critical, CA:FALSE" >> certs/san.conf; \
		echo "keyUsage = critical, digitalSignature, keyEncipherment" >> certs/san.conf; \
		echo "extendedKeyUsage = serverAuth" >> certs/san.conf; \
		echo "subjectKeyIdentifier = hash" >> certs/san.conf; \
		echo "authorityKeyIdentifier = keyid,issuer" >> certs/san.conf; \
		echo "subjectAltName = @alt_names" >> certs/san.conf; \
	fi
	@echo "🏛️ Creating Certificate Authority..."
	openssl ecparam -name prime256v1 -genkey -noout -out certs/ca-key.pem
	openssl pkcs8 -topk8 -nocrypt -in certs/ca-key.pem -out certs/ca-key-pkcs8.pem
	openssl req -new -x509 -key certs/ca-key-pkcs8.pem -out certs/ca-cert.pem -days 3650 -sha256 -config certs/ca.conf -extensions v3_ca
	@echo "🔐 Generating proxy private key..."
	openssl ecparam -name prime256v1 -genkey -noout -out certs/proxy-key.pem
	openssl pkcs8 -topk8 -nocrypt -in certs/proxy-key.pem -out certs/proxy-key-pkcs8.pem
	@echo "📄 Creating Certificate Signing Request (CSR)..."
	openssl req -new -key certs/proxy-key-pkcs8.pem -out certs/proxy.csr -config certs/san.conf -extensions v3_req
	@echo "🎯 Signing certificate with CA..."
	openssl x509 -req -in certs/proxy.csr -CA certs/ca-cert.pem -CAkey certs/ca-key-pkcs8.pem -CAcreateserial -out certs/proxy-cert.pem -days 365 -extensions v3_leaf -extfile certs/san.conf -sha256
	@echo "🔄 Converting to DER format..."
	openssl pkcs8 -in certs/proxy-key-pkcs8.pem -topk8 -nocrypt -outform DER -out certs/proxy-key.der
	openssl x509 -in certs/proxy-cert.pem -outform DER -out certs/proxy-cert.der
	@echo "📦 Creating full chain..."
	cat certs/proxy-cert.pem certs/ca-cert.pem > certs/proxy-fullchain.pem
	@echo "🔒 Setting secure permissions..."
	chmod 600 certs/proxy-key.pem certs/proxy-key-pkcs8.pem certs/proxy-key.der certs/ca-key.pem certs/ca-key-pkcs8.pem
	chmod 644 certs/proxy-cert.pem certs/proxy-cert.der certs/ca-cert.pem certs/proxy-fullchain.pem
	@echo "✅ CA-signed certificates created successfully!"

certs: certs-ca

certs-verify:
	@echo "🔍 Verifying certificate details..."
	openssl x509 -in certs/proxy-cert.pem -text -noout | head -20
	@echo ""
	@echo "🔍 Checking SAN extensions..."
	openssl x509 -in certs/proxy-cert.pem -text -noout | grep -A 10 "Subject Alternative Name"
	@echo ""
	@echo "📅 Checking validity period..."
	openssl x509 -in certs/proxy-cert.pem -noout -dates
	@echo ""
	@if [ -f certs/ca-cert.pem ]; then \
		echo "🔍 Checking CA constraints/key usage..."; \
		openssl x509 -in certs/ca-cert.pem -noout -text | grep -A 4 -E "Basic Constraints|Key Usage"; \
		echo ""; \
	fi
	@if [ -f certs/ca-cert.pem ]; then \
		echo "✅ Verifying against CA..."; \
		openssl verify -CAfile certs/ca-cert.pem certs/proxy-cert.pem; \
	fi

certs-clean:
	@echo "🧹 Cleaning certificate files..."
	rm -f certs/*

clean:
	rm -f target/release/impulse
