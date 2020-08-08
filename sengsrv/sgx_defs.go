package main

/* TODO: auto generate from SGX C header files (sgx_quote.h, sgx_report.h, ...) */

const sgxCPUSvnSize = 16

type sgxCPUSvn struct {
	Svn [sgxCPUSvnSize]uint8
}

type sgxMiscSelect uint32

const sgxReportBodyReserved1Bytes = 12
const sgxReportBodyReserved2Bytes = 32
const sgxReportBodyReserved3Bytes = 32
const sgxReportBodyReserved4Bytes = 42

const sgxIsvextProdIDSize = 16
const sgxIsvFamilyIDSize = 16

type sgxIsvextProdID [sgxIsvextProdIDSize]uint8
type sgxIsvfamilyID [sgxIsvFamilyIDSize]uint8
type sgxProdID uint16

// sgx_attributes.h
type sgxAttributes struct {
	Flags uint64
	Xfrm  uint64
}

const sgxConfigIDSize = 64

type sgxConfigSvn uint16
type sgxConfigID [sgxConfigIDSize]uint8

const sgxHashSize = 32 // SHA256

type sgxMeasurement struct {
	M [sgxHashSize]uint8
}

// sgx_report.h
type sgxReportBody struct {
	CpuSVN       sgxCPUSvn
	MiscSelect   sgxMiscSelect
	Reserved1    [sgxReportBodyReserved1Bytes]uint8
	IsvExtProdID sgxIsvextProdID
	Attributes   sgxAttributes
	MrEnclave    sgxMeasurement
	Reserved2    [sgxReportBodyReserved2Bytes]uint8
	MrSigner     sgxMeasurement
	Reserved3    [sgxReportBodyReserved3Bytes]uint8
	ConfigID     sgxConfigID
	IsvProdID    sgxProdID
	IsvSVN       sgxIsvSvn
	ConfigSVN    sgxConfigSvn
	Reserved4    [sgxReportBodyReserved4Bytes]uint8
	IsvFamilyID  sgxIsvfamilyID
	ReportData   sgxReportData
}

const sgxReportDataSize = 64

type sgxReportData struct {
	D [sgxReportDataSize]uint8
}

// sgx_quote.h
type sgxEPIDGroupID [4]uint8
type sgxIsvSvn uint16

type sgxBasename struct {
	Name [32]uint8
}

type sgxQuote struct {
	Version     uint16
	SignType    uint16
	EpidGroupID sgxEPIDGroupID
	QeSVN       sgxIsvSvn
	PceSVN      sgxIsvSvn
	Xeid        uint32
	Basename    sgxBasename
	ReportBody  sgxReportBody
	/* the signature fields are dropped to be constant size
	 * ++ because signature is passed via separate x509 extension */
	//signatureLen uint32
	//signature    *[]uint8
}
