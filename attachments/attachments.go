// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package attachments

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coming-chat/coming-go-v2/constant"
	"github.com/coming-chat/coming-go-v2/crypto"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	signalservice "github.com/coming-chat/coming-go-v2/protobuf"
	textsecure "github.com/coming-chat/coming-go-v2/protobuf"
	"github.com/coming-chat/coming-go-v2/transport"
	log "github.com/sirupsen/logrus"
)

type AttachmentPointerV3 struct {
	CdnKey    string
	CdnNr     uint32
	Ct        string
	Keys      []byte
	Digest    []byte
	Size      uint32
	VoiceNote bool
}

// Attachment represents an attachment received from a peer
type Attachment struct {
	R        io.Reader
	MimeType string
	FileName string
}

// Attachment handling
type AttachmentV3UploadAttributes struct {
	Cdn                  uint32            `json:"cdn"`
	Key                  string            `json:"key"`
	Headers              map[string]string `json:"headers"`
	SignedUploadLocation string            `json:"signedUploadLocation"`
}

func getProfileLocation(profilePath string) string {
	cdn := constant.SIGNAL_CDN_URL
	return cdn + fmt.Sprintf(profilePath)
}

// getAttachment downloads an encrypted attachment blob from the given URL
func getAttachment(url string) (io.ReadCloser, error) {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	c := &http.Client{Transport: customTransport}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Host", constant.SERVICE_REFLECTOR_HOST)
	req.Header.Add("Content-Type", "application/octet-stream")

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

// putAttachment uploads an encrypted attachment to the given relative URL using the CdnTransport
func putAttachmentV3(url string, body []byte) ([]byte, error) {
	response, err := transport.CdnTransport.Put(url, body, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	if response.IsError() {
		return nil, response
	}
	hasher := sha256.New()
	hasher.Write(body)

	return hasher.Sum(nil), nil
}

// uploadAttachment encrypts, authenticates and uploads a given attachment to a location requested from the server
func UploadAttachment(r io.Reader, ct string) (*AttachmentPointerV3, error) {
	return uploadAttachmentV3(r, ct, false)
}

func UploadProfileAvatar(avatar []byte, info *signalservice.AvatarUploadAttributes) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	err := writer.WriteField("key", info.GetKey())
	if err != nil {
		return err
	}
	err = writer.WriteField("acl", info.GetAcl())
	if err != nil {
		return err
	}
	err = writer.WriteField("x-amz-credential", info.GetCredential())
	if err != nil {
		return err
	}
	err = writer.WriteField("x-amz-date", info.GetDate())
	if err != nil {
		return err
	}
	err = writer.WriteField("x-amz-signature", info.GetSignature())
	if err != nil {
		return err
	}
	err = writer.WriteField("policy", info.GetPolicy())
	if err != nil {
		return err
	}
	err = writer.WriteField("x-amz-algorithm", info.GetAlgorithm())
	if err != nil {
		return err
	}
	err = writer.WriteField("Content-Type", "application/octet-stream")
	if err != nil {
		return err
	}
	file, err := writer.CreateFormField("file")
	if err != nil {
		return err
	}
	_, err = file.Write(avatar)
	if err != nil {
		return err
	}
	err = writer.Close()
	if err != nil {
		return err
	}
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	c := &http.Client{Transport: customTransport}
	req, err := http.NewRequest(http.MethodPost, constant.SIGNAL_CDN_URL, body)
	req.Header.Add("Content-Type", writer.FormDataContentType())

	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		respData, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload %s get err: %s", constant.SIGNAL_CDN_URL, respData)
	}
	return nil
}

// uploadAttachmentV3 encrypts, authenticates and uploads a given attachment to a location requested from the server
func uploadAttachmentV3(r io.Reader, ct string, isVoiceNote bool) (*AttachmentPointerV3, error) {
	//combined AES-256 and HMAC-SHA256 key
	keys := make([]byte, 64)
	crypto.RandBytes(keys)

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	plaintextLength := len(b)

	e, err := crypto.AesEncrypt(keys[:32], b)
	if err != nil {
		return nil, err
	}

	m := crypto.AppendMAC(keys[32:], e)

	location, uploadAttributes, err := allocateAttachmentV3()
	if err != nil {
		return nil, err
	}
	digest, err := putAttachmentV3(location, m)
	if err != nil {
		return nil, err
	}
	return &AttachmentPointerV3{uploadAttributes.Key, uploadAttributes.Cdn, ct, keys, digest, uint32(plaintextLength), isVoiceNote}, nil
}

func UploadVoiceNote(r io.Reader, ct string) (*AttachmentPointerV3, error) {
	return uploadAttachmentV3(r, "audio/mpeg", true)
}

// ErrInvalidMACForAttachment signals that the downloaded attachment has an invalid MAC.
var ErrInvalidMACForAttachment = errors.New("invalid MAC for attachment")

func HandleSingleAttachment(a *textsecure.AttachmentPointer) (*Attachment, error) {
	loc, err := getAttachmentLocation(a.GetCdnId(), a.GetCdnKey(), a.GetCdnNumber())
	if err != nil {
		return nil, err
	}
	r, err := getAttachment(loc)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	l := len(b) - 32
	if !crypto.VerifyMAC(a.Key[32:], b[:l], b[l:]) {
		return nil, ErrInvalidMACForAttachment
	}

	b, err = crypto.AesDecrypt(a.Key[:32], b[:l])
	if err != nil {
		return nil, err
	}

	// TODO: verify digest

	return &Attachment{bytes.NewReader(b), a.GetContentType(), a.GetFileName()}, nil
}

func HandleProfileAvatar(profileAvatar *signalservice.ContactDetails_Avatar, key []byte) (*Attachment, error) {

	loc := getProfileLocation(profileAvatar.String())
	r, err := getAttachment(loc)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	l := len(b) - 16
	if !crypto.VerifyMAC(key[16:], b[:l], b[l:]) {
		return nil, ErrInvalidMACForAttachment
	}

	b, err = crypto.AesDecrypt(key[:16], b[:l])
	if err != nil {
		return nil, err
	}

	// TODO: verify digest

	return &Attachment{bytes.NewReader(b), profileAvatar.GetContentType(), ""}, nil
}

func HandleAttachments(dm *textsecure.DataMessage) ([]*Attachment, error) {
	atts := dm.GetAttachments()
	if atts == nil {
		return nil, nil
	}

	all := make([]*Attachment, len(atts))
	var err error
	for i, a := range atts {
		all[i], err = HandleSingleAttachment(a)
		if err != nil {
			return nil, err
		}
	}
	return all, nil
}

func getAttachmentV3UploadAttributes() (*AttachmentV3UploadAttributes, error) {
	resp, err := transport.ServiceTransport.Get(constant.ATTACHMENT_V3_PATH)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(resp.Body)
	var a AttachmentV3UploadAttributes
	err = dec.Decode(&a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func relativePath(url string) string {
	parts := strings.Split(url, "/")
	return "/" + strings.Join(parts[3:], "/")
}

func (a *AttachmentV3UploadAttributes) relativeSignedUploadLocation() string {
	return relativePath(a.SignedUploadLocation)
}

func allocateAttachmentV3() (string, *AttachmentV3UploadAttributes, error) {
	uploadAttributes, err := getAttachmentV3UploadAttributes()
	if err != nil {
		return "", nil, err
	}
	resp, err := transport.CdnTransport.PostWithHeaders(
		uploadAttributes.relativeSignedUploadLocation(),
		[]byte{},
		"application/octet-stream",
		uploadAttributes.Headers)
	if err != nil {
		return "", nil, err
	}
	if resp.IsError() {
		log.Debug("[textsecure] allocateAttachmentV3 error response ", resp.Body)
		return "", nil, resp
	}
	location := resp.Header.Get("Location")
	return relativePath(location), uploadAttributes, nil
}

func getAttachmentLocation(id uint64, key string, cdnNumber uint32) (string, error) {
	cdn := constant.SIGNAL_CDN_URL
	if cdnNumber == 2 {
		cdn = constant.SIGNAL_CDN2_URL
	}
	if id != 0 {
		return cdn + fmt.Sprintf(constant.ATTACHMENT_ID_DOWNLOAD_PATH, id), nil
	}
	return cdn + fmt.Sprintf(constant.ATTACHMENT_KEY_DOWNLOAD_PATH, key), nil
}
