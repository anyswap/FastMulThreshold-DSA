package smpctee

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/ego/eclient"
	"github.com/edgelesssys/ego/enclave"
	"github.com/edgelesssys/ego/ecrypto"
)

func CreateCertificate(pk []byte ) ([]byte, error) {
	hash := sha256.Sum256(pk)
	report, err := enclave.GetRemoteReport(hash[:])
	return report, err
}

func VerifyReport(reportBytes, pk, expectedUniqueID []byte, expectedSecurityVersion, expectedProductID int, expectedDebugMode bool) (bool, error) {
	report, err := eclient.VerifyRemoteReport(reportBytes)
	if err == attestation.ErrTCBLevelInvalid {
		fmt.Printf("Warning: TCB level is invalid: %v\n%v\n", report.TCBStatus, tcbstatus.Explain(report.TCBStatus))
	} else if err != nil {
		return false, err
	}

	hash := sha256.Sum256(pk)
	if !bytes.Equal(report.Data[:len(hash)], hash[:]) {
		return false, errors.New("report data does not match the certificate's hash")
	}

	if !bytes.Equal(report.UniqueID, expectedUniqueID) {
		return false, errors.New("invalid uniqueID")
	}
	if report.SecurityVersion < uint(expectedSecurityVersion) {
		return false, errors.New("invalid security version")
	}
	if binary.LittleEndian.Uint16(report.ProductID) != uint16(expectedProductID) {
		return false, errors.New("invalid productID")
	}
	if report.Debug != expectedDebugMode {
		return false, errors.New("invalid debug mode")
	}

	return true, nil
}

func EncryptByProductKey(plaintext []byte) ([]byte, error){
	return ecrypto.SealWithProductKey(plaintext, nil)
}

func DecryptByProductKey(ciphertext []byte) ([]byte, error){
	return ecrypto.Unseal(ciphertext, nil)
}

// must save keyInfo, which is used to retrieve the same key on a newer TEE CPU
func GetProductKeyInfo() ([]byte, error){
	_, keyInfo, err := enclave.GetProductSealKey()
	return keyInfo, err
}