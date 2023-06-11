package ecies

import "crypto/elliptic"

func getCurve() elliptic.Curve {
	// https://datatracker.ietf.org/doc/html/rfc4492#appendix-A
	// ------------------------------------------
	//           Curve names chosen by
	//      different standards organizations
	// ------------+---------------+-------------
	// SECG        |  ANSI X9.62   |  NIST
	// ------------+---------------+-------------
	// sect163k1   |               |   NIST K-163
	// sect163r1   |               |
	// sect163r2   |               |   NIST B-163
	// sect193r1   |               |
	// sect193r2   |               |
	// sect233k1   |               |   NIST K-233
	// sect233r1   |               |   NIST B-233
	// sect239k1   |               |
	// sect283k1   |               |   NIST K-283
	// sect283r1   |               |   NIST B-283
	// sect409k1   |               |   NIST K-409
	// sect409r1   |               |   NIST B-409
	// sect571k1   |               |   NIST K-571
	// sect571r1   |               |   NIST B-571
	// secp160k1   |               |
	// secp160r1   |               |
	// secp160r2   |               |
	// secp192k1   |               |
	// secp192r1   |  prime192v1   |   NIST P-192
	// secp224k1   |               |
	// secp224r1   |               |   NIST P-224
	// secp256k1   |               |
	// secp256r1   |  prime256v1   |   NIST P-256
	// secp384r1   |               |   NIST P-384
	// secp521r1   |               |   NIST P-521
	// ------------+---------------+-------------
	return elliptic.P384() // secp384r1
}
