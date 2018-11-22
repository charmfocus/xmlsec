package xmlsec

import (
	"io"

	"crypto/sha1"

	"bufio"
	"bytes"
	"io/ioutil"

	"encoding/base64"

	"crypto"
	"strings"

	"errors"

	"github.com/tinyhubs/tinydom"
)

const (
	RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	XMLDSIGNS  = "http://www.w3.org/2000/09/xmldsig#"
	SHA1       = "http://www.w3.org/2000/09/xmldsig#sha1"
	SHA256     = "http://www.w3.org/2001/04/xmlenc#sha256"
	C14N       = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	EnvSign    = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

type XmlSec struct {
	XMLDocument tinydom.XMLDocument
}

func newXmlSec(reader io.Reader) (*XmlSec, error) {
	xmlSec := new(XmlSec)
	doc, err := tinydom.LoadDocument(reader)
	if err != nil {
		return xmlSec, err
	}
	xmlSec.XMLDocument = doc
	return xmlSec, err
}

func Sign(data []byte, privateKey []byte) (value []byte, err error) {
	return getSignElement(data, privateKey)
}

func getSignElement(data []byte, privateKey []byte) (value []byte, err error) {
	signElement, err := newXmlSec(bytes.NewReader(data))
	if err != nil {
		return value, err
	}
	signElement.addSignatureElement(privateKey)
	signElement.XMLDocument.InsertFirstChild(tinydom.NewProcInst("xml", `version="1.0" encoding="UTF-8"`))
	value, err = elementToBytes(signElement.XMLDocument)
	return
}

func (this *XmlSec) addSignatureElement(privateKey []byte) error {
	documentElement := this.XMLDocument.FirstChildElement("document")
	signatureElement := tinydom.NewElement("ds:Signature")
	signatureElement.SetAttribute("xmlns:ds", XMLDSIGNS)
	//需要签名的内容开始
	signedInfoElement := tinydom.NewElement("ds:SignedInfo")

	canonicalizationMethodElement := tinydom.NewElement("ds:CanonicalizationMethod")
	canonicalizationMethodElement.SetAttribute("Algorithm", C14N)

	signatureMethodElement := tinydom.NewElement("ds:SignatureMethod")
	signatureMethodElement.SetAttribute("Algorithm", RSA_SHA256)

	referenceElement := tinydom.NewElement("ds:Reference")
	referenceElement.SetAttribute("URI", "")

	transformsElement := tinydom.NewElement("ds:Transforms")

	transformElement := tinydom.NewElement("ds:SignatureMethod")
	transformElement.SetAttribute("Algorithm", EnvSign)

	digestMethodElement := tinydom.NewElement("ds:DigestMethod")
	digestMethodElement.SetAttribute("Algorithm", SHA1)

	//<ds:DigestValue></ds:DigestValue>
	//sha1 签名
	documentValue, err := elementToBytes(documentElement)
	if err != nil {
		return err
	}
	digestValue := this.createSha1(documentValue)
	digestValueElement := tinydom.NewElement("ds:DigestValue")
	digestValueElement.SetText(digestValue)

	digestMethodElement.InsertEndChild(digestValueElement)
	transformElement.InsertEndChild(digestMethodElement)
	transformsElement.InsertEndChild(transformElement)
	referenceElement.InsertEndChild(transformsElement)
	signatureMethodElement.InsertEndChild(referenceElement)
	canonicalizationMethodElement.InsertEndChild(signatureMethodElement)
	signedInfoElement.InsertEndChild(canonicalizationMethodElement)
	signatureElement.InsertEndChild(signedInfoElement)

	//需要签名的内容结束
	//reaSha256 签名
	signeValue, err := elementToBytes(signedInfoElement)
	if err != nil {
		return err
	}
	//signinfo签名
	signeValueText, err := this.rsaSha256Encode(signeValue, privateKey)
	if err != nil {
		return err
	}
	signatureValueElement := tinydom.NewElement("ds:SignatureValue")
	signatureValueElement.SetText(signeValueText)
	signatureElement.InsertEndChild(signatureValueElement)
	documentElement.InsertEndChild(signatureElement)
	return nil
}

func elementToBytes(element tinydom.XMLDocument) (value []byte, err error) {
	byteBuffer := bytes.NewBuffer(make([]byte, 0))
	bufioWriter := bufio.NewWriter(byteBuffer)

	tinydom.SaveDocument(element, bufioWriter, tinydom.PrintStream)
	bufioWriter.Flush()
	value, err = ioutil.ReadAll(byteBuffer)
	return
}

func (this *XmlSec) rsaSha256Encode(src []byte, privateKey []byte) (string, error) {
	sig, err := signPKCS1v15(src, privateKey, crypto.SHA256)
	if err != nil {
		return "", err
	}
	sign := base64.StdEncoding.EncodeToString(sig)
	return sign, nil
}

func (this *XmlSec) createSha1(s []byte) string {
	h := sha1.New()
	h.Write(s)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func VerifySign(data []byte, publicKey []byte) (bool, error) {
	signElement, err := newXmlSec(bytes.NewReader(data))
	if err != nil {
		return false, err
	}
	doc := signElement.XMLDocument
	eml := doc.FirstChildElement("document").FirstChildElement("Signature").FirstChildElement("SignatureValue")
	if eml == nil {
		return false, errors.New("未取到sign")
	}
	signatureValue := eml.Text()
	signatureValue=strings.Replace(signatureValue," ","",-1)
	if len(signatureValue) < 1 {
		return false, errors.New("未取到sign")
	}

	signValue := canonicalizeSignedInfo(data)
	s, err := ioutil.ReadAll(signValue)
	if err != nil {
		return false, err
	}
	return rsaSha256Decode(s, signatureValue, publicKey)
}

func canonicalizeSignedInfo(data []byte) *bytes.Buffer {
	writeBuffer := bytes.NewBuffer(make([]byte, 0))
	byteBuffer := bytes.NewBuffer(data)
	bufioReader := bufio.NewReader(byteBuffer)
	start := false
	for {
		str, err := bufioReader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.Contains(str, `<SignedInfo>`) {
			str = strings.Replace(str, `<SignedInfo>`, `<SignedInfo xmlns="`+XMLDSIGNS+`">`, -1)
			start = true
		}
		if start {
			if strings.Contains(str, `</SignedInfo>`) {
				if strings.Contains(str,`<SignatureValue>`){
					//查找<SignedInfo>出现的位置
					st:=strings.Index(str, `<SignedInfo`)
					//查找<SignedInfo>出现的位置
					en:=strings.LastIndex(str, `</SignedInfo>`)+len(`</SignedInfo>`)
					strRune:=[]rune(str)
					str=string(strRune[st:en])
				}
				line := []byte(str)
				if len(line) > 0 && line[len(line)-1] == '\n' {
					line = line[:len(line)-1]
				}
				if len(line) > 0 && line[len(line)-1] == '\r' {
					line = line[:len(line)-1]
				}
				writeBuffer.WriteString(string(line))
				break
			}
			writeBuffer.WriteString(str)
		}
	}
	return writeBuffer
}

func rsaSha256Decode(data []byte, sign string, publicKey []byte) (bool, error) {
	signBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return false, err
	}
	err = verifyPKCS1v15(data, signBytes, publicKey, crypto.SHA256)
	if err != nil {
		return false, err
	}
	return true, nil
}
