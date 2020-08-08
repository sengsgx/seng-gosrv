package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

/* based on sgx ra-tls */
//var baseOIDBytes = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39}
var baseOID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1337}
var iasResponseBodyOID = append(baseOID[:], 0x02)
var iasRootCertOID = append(baseOID[:], 0x03)
var iasLeafCertOID = append(baseOID[:], 0x04)
var iasReportSignatureOID = append(baseOID[:], 0x05)

type rawSgxExtensionData struct {
	iasReport          []byte
	iasCaCert          []byte
	iasCert            []byte
	iasReportSignature []byte
}

func getDecodeQuoteFromIASReport(iasReport []byte) (quote *sgxQuote, err error) {
	quoteBodyStr := []byte("\"isvEnclaveQuoteBody\":\"")
	idx := bytes.Index(iasReport, quoteBodyStr)
	if idx == -1 {
		return nil, errors.New("Failed to find IAS quote status")
	}
	idx += len(quoteBodyStr)
	endIdx := bytes.Index(iasReport[idx:], []byte("\""))
	if endIdx == -1 {
		return nil, errors.New("Failed to parse IAS quote status")
	}
	encodedQuote := iasReport[idx:(idx + endIdx)]
	quoteBuf := make([]byte, base64.StdEncoding.DecodedLen(len(encodedQuote)))
	var n int
	if n, err = base64.StdEncoding.Decode(quoteBuf, encodedQuote); err != nil {
		return nil, errors.New("Failed to decode quote body: " + err.Error())
	}
	quoteBuf = quoteBuf[:n]

	br := bytes.NewBuffer(quoteBuf)
	quote = &sgxQuote{}
	if err := binary.Read(br, binary.LittleEndian, quote); err != nil {
		return nil, errors.New("Failed to parse decoded quote body: " + err.Error())
	}

	return
}

// Note: follows flow of sgx ra-tls
func (sgxExt *rawSgxExtensionData) verify(cert *x509.Certificate) (quote *sgxQuote, err error) {
	// TODO: check that attestation report not older than ~ 2 minutes / 1 day?

	/* verify IAS certificate chain */
	var iasCert, iasCaCert *x509.Certificate
	if iasCert, err = x509.ParseCertificate(sgxExt.iasCert); err != nil {
		return nil, errors.New("Failed parsing iasCert: " + err.Error())
	}
	if iasCaCert, err = x509.ParseCertificate(sgxExt.iasCaCert); err != nil {
		return nil, errors.New("Failed parsing iasCaCert: " + err.Error())
	}
	if err = iasCert.CheckSignatureFrom(iasCaCert); err != nil {
		return nil, errors.New("CheckSignatureForm failed (iasCaCert, iasCert): " + err.Error())
	}

	// check against downloaded IAS Root CA Certificate
	var iasRootCaCert *x509.Certificate
	if iasRootCaCert, err = loadIASRootCa(iasRootCaPath); err != nil {
		return nil, errors.New("Failed to load IAS Root CA Cert from: " + iasRootCaPath + "(err: " + err.Error() + ")")
	}
	if err = iasCaCert.CheckSignatureFrom(iasRootCaCert); err != nil {
		return nil, errors.New("CheckSignatureFrom failed (iasRootCaCert, iasCaCert): " + err.Error())
	}

	/* verify IAS report signature */

	// Warning: currently only RSA supported for IAS
	iasPkey := iasCert.PublicKey.(*rsa.PublicKey)
	hash := sha256.Sum256(sgxExt.iasReport)
	if err = rsa.VerifyPKCS1v15(iasPkey, crypto.SHA256, hash[:], sgxExt.iasReportSignature); err != nil {
		return nil, errors.New("Signature of iasReport seems broken: " + err.Error())
	}

	/* verify enclave quote status */
	quoteStatusStr := []byte("\"isvEnclaveQuoteStatus\":\"")
	idx := bytes.Index(sgxExt.iasReport, quoteStatusStr)
	if idx == -1 {
		return nil, errors.New("Failed to find IAS quote status")
	}
	idx += len(quoteStatusStr)
	okStr := []byte("OK\"")
	if !bytes.HasPrefix(sgxExt.iasReport[idx:], okStr) {
		outdatedStr := []byte("GROUP_OUT_OF_DATE\"")
		if !bytes.HasPrefix(sgxExt.iasReport[idx:], outdatedStr) {
			return nil, errors.New("Invalid IAS quote status")
		}
		fmt.Fprintln(os.Stderr, "Warning: isvEnclaveQuoteStatus is GROUP_OUT_OF_DATE")
	}

	/* get decoded quote from IAS body */
	if quote, err = getDecodeQuoteFromIASReport(sgxExt.iasReport); err != nil {
		return
	}

	/* verify report data against server cert */
	/* RSA
	cliPkey := cert.PublicKey.(*rsa.PublicKey)
	sum256 := sha256.Sum256(x509.MarshalPKCS1PublicKey(cliPkey))
	*/

	/* ECDSA */
	cliPkey := cert.PublicKey.(*ecdsa.PublicKey)
	// successfully tested this hashing against client-side's hashing
	sum256 := sha256.Sum256(elliptic.Marshal(cliPkey, cliPkey.X, cliPkey.Y))
	if 0 != bytes.Compare(sum256[:], quote.ReportBody.ReportData.D[:32]) {
		return nil, errors.New("Client certficiate public key hash != SGX report user data")
	}

	fmt.Println("SGX Extension checks: Success!")
	return
}

func findDecodedSGXExtension(extension asn1.ObjectIdentifier, cert *x509.Certificate) (decodedExt []byte, err error) {
	ext, err := findSGXExtension(extension, cert)
	if err != nil {
		return
	}
	// base64 decode the extension value
	decodedExt = make([]byte, base64.StdEncoding.DecodedLen(len(ext.Value)))
	var n int
	n, err = base64.StdEncoding.Decode(decodedExt, ext.Value)
	if _, err = base64.StdEncoding.Decode(decodedExt, ext.Value); err != nil {
		decodedExt = nil
		return
	}
	// get rid of padding to avoid "asn1: syntax error: trailing data"
	decodedExt = decodedExt[:n]
	return
}

func findSGXExtension(extension asn1.ObjectIdentifier, cert *x509.Certificate) (ext pkix.Extension, err error) {
	for _, ext = range cert.Extensions {
		/*
			fmt.Println("ID:", ext.Id)
			fmt.Println("Critical:", ext.Critical)
			fmt.Println("Value:", ext.Value)
		*/
		// found
		if ext.Id.Equal(extension) {
			return
		}
	}
	err = errors.New("Failed to find required SGX metadata in client certificate")
	return
}

const iasRootCaPath = "./Intel_SGX_Attestation_RootCA.pem"

func loadIASRootCa(path string) (cert *x509.Certificate, err error) {
	var buffer []byte
	buffer, err = ioutil.ReadFile(path)
	if err != nil {
		return
	}
	block, _ := pem.Decode(buffer)
	if block == nil {
		return nil, errors.New("Failed to decode IAS Root CA PEM")
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	return
}

func extractQuoteFromRawCert(rawCert []byte) (quote *sgxQuote, err error) {
	var cert *x509.Certificate
	if cert, err = x509.ParseCertificate(rawCert); err != nil {
		return
	}

	// get ias report
	var iasReport []byte
	if iasReport, err = findDecodedSGXExtension(iasResponseBodyOID, cert); err != nil {
		return
	}

	quote, err = getDecodeQuoteFromIASReport(iasReport)
	return
}

func (s *sengServer) verifyTunnelEnclave(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (err error) {
	fmt.Println("Performing remote attestation - certificate checks")
	// TODO: only consider the leaf certificate for the SGX extensions!
	for _, rc := range rawCerts {
		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(rc)
		if err != nil {
			return errors.New("Failed to parse client certificate: " + err.Error())
		}
		// fmt.Println(cert)
		/* Extract SGX attestation information */
		var sgxInfo rawSgxExtensionData
		if sgxInfo.iasReport, err = findDecodedSGXExtension(iasResponseBodyOID, cert); err != nil {
			continue
		}

		if sgxInfo.iasCaCert, err = findDecodedSGXExtension(iasRootCertOID, cert); err != nil {
			continue
		}

		if sgxInfo.iasCert, err = findDecodedSGXExtension(iasLeafCertOID, cert); err != nil {
			continue
		}

		if sgxInfo.iasReportSignature, err = findDecodedSGXExtension(iasReportSignatureOID, cert); err != nil {
			continue
		}

		// found! (TODO: only consider leaf certificate)
		var quote *sgxQuote
		if quote, err = sgxInfo.verify(cert); err != nil {
			continue
		} else {
			fmt.Print("SGX Measurement: ")
			for _, c := range quote.ReportBody.MrEnclave.M {
				fmt.Printf("%02x", c)
			}
			fmt.Println()
			break // success
		}
	}
	return
}
