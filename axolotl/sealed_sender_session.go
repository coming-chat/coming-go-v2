package axolotl

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"github.com/coming-chat/coming-go-v2/crypto"
	"github.com/coming-chat/coming-go-v2/curve25519sign"
	protobuf "github.com/coming-chat/coming-go-v2/protobuf"
	"github.com/golang/protobuf/proto"
)

const CIPHERTEXT_VERSION uint8 = 1

var REVOKED_SERVER_CERTIFICATE_KEY_IDS = []uint32{0xDEADC357}

type ServerCertificate struct {
	keyId       uint32
	key         ECPublicKey
	certificate []byte
	signature   []byte
}

func NewServerCertificate(wrapper *protobuf.ServerCertificate) (*ServerCertificate, error) {
	if len(wrapper.Certificate) == 0 || len(wrapper.Signature) == 0 {
		return nil, errors.New("InvalidProtobufEncoding")
	}

	scc := &protobuf.ServerCertificate_Certificate{}
	err := proto.Unmarshal(wrapper.Certificate, scc)
	if err != nil {
		return nil, err
	}

	if len(scc.Key) == 0 || scc.Id == nil {
		return nil, errors.New("InvalidProtobufEncoding")
	}

	return &ServerCertificate{
		keyId:       *scc.Id,
		key:         NewECPublicKey(scc.Key[1:33]),
		certificate: wrapper.Certificate,
		signature:   wrapper.Signature,
	}, nil
}

func (s *ServerCertificate) validate(trustRoot ECPublicKey) bool {
	for _, v := range REVOKED_SERVER_CERTIFICATE_KEY_IDS {
		if v == s.keyId {
			return false
		}
	}
	var signature [64]byte
	copy(signature[:], s.signature)
	return curve25519sign.Verify(trustRoot, s.certificate, &signature)
}

type SenderCertificate struct {
	Signer         *ServerCertificate
	Key            ECPublicKey
	SenderDeviceId uint32
	SenderUuid     string
	SenderE164     string
	Expiration     uint64
	Certificate    []byte
	Signature      []byte
}

func NewSenderCertificate(wrapper *protobuf.SenderCertificate) (*SenderCertificate, error) {
	if wrapper == nil {
		return nil, errors.New("nil data")
	}
	certificate := &protobuf.SenderCertificate_Certificate{}
	err := proto.Unmarshal(wrapper.GetCertificate(), certificate)
	if err != nil {
		return nil, err
	}
	if certificate.SenderDevice == nil || certificate.Expires == nil || certificate.IdentityKey == nil || certificate.Signer == nil {
		return nil, errors.New("InvalidCertificate")
	}
	if certificate.GetSenderE164() == "" && certificate.GetSenderUuid() == "" {
		return nil, errors.New("InvalidCertificate")
	}
	serverCertificate, err := NewServerCertificate(certificate.GetSigner())
	if err != nil {
		return nil, err
	}
	return &SenderCertificate{
		Signer:         serverCertificate,
		Key:            NewECPublicKey(certificate.GetIdentityKey()[1:33]),
		SenderDeviceId: certificate.GetSenderDevice(),
		SenderUuid:     certificate.GetSenderUuid(),
		SenderE164:     certificate.GetSenderE164(),
		Expiration:     certificate.GetExpires(),
		Certificate:    wrapper.GetCertificate(),
		Signature:      wrapper.GetSignature(),
	}, nil
}

type CertificateValidator struct {
	TrustRoot ECPublicKey
}

func (c *CertificateValidator) validate(certificate *SenderCertificate, validationTime uint64) error {
	signer := certificate.Signer
	if !signer.validate(c.TrustRoot) {
		return errors.New("InvalidCertificate")
	}

	var certSignature [64]byte
	copy(certSignature[:], certificate.Signature)
	if !curve25519sign.Verify(signer.key, certificate.Certificate, &certSignature) {
		return errors.New("InvalidCertificate")
	}

	if validationTime > certificate.Expiration {
		return errors.New("ExpiredCertificate")
	}
	return nil
}

type SealedSessionCipher struct {
	*SessionCipher
	CertificateValidator CertificateValidator
}

func NewSealedSessionCipher(cipher *SessionCipher, trustRoot ECPublicKey) *SealedSessionCipher {
	return &SealedSessionCipher{
		cipher,
		CertificateValidator{
			trustRoot,
		},
	}
}

type EphemeralKeys struct {
	ChainKey  []byte
	CipherKey []byte
	MacKey    []byte
}

type DecryptionResult struct {
	SenderUuid    string
	SenderE164    string
	DeviceId      uint32
	PaddedMessage []byte
	Version       uint32
}

type StaticKeys struct {
	CipherKey []byte
	MacKey    []byte
}

type UnidentifiedSenderMessage struct {
	ephemeral        ECPublicKey
	encryptedStatic  []byte
	encryptedMessage []byte
}

func NewUnidentifiedSenderMessage(data []byte) (*UnidentifiedSenderMessage, error) {
	version := data[0] >> 4
	if version > CIPHERTEXT_VERSION {
		return nil, errors.New("InvalidMetadataVersionError")
	}
	unidentifiedSenderMessage := &protobuf.UnidentifiedSenderMessage{}
	err := proto.Unmarshal(data[1:], unidentifiedSenderMessage)
	if err != nil {
		return nil, err
	}
	if len(unidentifiedSenderMessage.GetEncryptedMessage()) == 0 || len(unidentifiedSenderMessage.GetEncryptedStatic()) == 0 || len(unidentifiedSenderMessage.GetEphemeralPublic()) == 0 {
		return nil, errors.New("InvalidMetadataMessageError")
	}
	return &UnidentifiedSenderMessage{
		ephemeral:        NewECPublicKey(unidentifiedSenderMessage.EphemeralPublic[1:]),
		encryptedStatic:  unidentifiedSenderMessage.EncryptedStatic,
		encryptedMessage: unidentifiedSenderMessage.EncryptedMessage,
	}, nil
}

func calculateKeysAndDerived(publicKey ECPublicKey, privateKey ECPrivateKey, salt, info []byte, size int) ([]byte, error) {
	ephemeralSecret, err := CalculateAgreement(publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return DeriveSecrets(
		ephemeralSecret[:],
		salt,
		info,
		size,
	)
}

func CalculateEphemeralKeys(publicKey ECPublicKey, privateKey ECPrivateKey, salt []byte) (*EphemeralKeys, error) {
	ephemeralDerived, err := calculateKeysAndDerived(publicKey, privateKey, salt, nil, 96)
	if err != nil {
		return nil, err
	}
	return &EphemeralKeys{
		ChainKey:  ephemeralDerived[:32],
		CipherKey: ephemeralDerived[32:64],
		MacKey:    ephemeralDerived[64:96],
	}, nil
}

func (s *SealedSessionCipher) decryptBytes(cipherKey, macKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 10 {
		return nil, errors.New("mac err")
	}

	ciphertextPart1 := ciphertext[:len(ciphertext)-10]
	theirMac := ciphertext[len(ciphertext)-10:]

	if !crypto.VerifyMAC(macKey, ciphertextPart1, theirMac) {
		return nil, errors.New("bad mac")
	}
	nonce := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	return crypto.AESCtrEncrypt(cipherKey, nonce[:], ciphertextPart1)
}

func (s *SealedSessionCipher) calculateStaticKeys(publicKey ECPublicKey, privateKey ECPrivateKey, salt []byte) (*StaticKeys, error) {
	staticDerived, err := calculateKeysAndDerived(publicKey, privateKey, salt, nil, 96)
	if err != nil {
		return nil, err
	}
	return &StaticKeys{
		CipherKey: staticDerived[32:64],
		MacKey:    staticDerived[64:96],
	}, nil
}

func (s *SealedSessionCipher) Decrypt(ciphertext []byte, timestamp uint64) (*DecryptionResult, error) {
	ourIdentity, err := s.Builder.identityStore.GetIdentityKeyPair()
	if err != nil {
		return nil, err
	}
	wrapper, err := NewUnidentifiedSenderMessage(ciphertext)
	if err != nil {
		return nil, err
	}

	ephemeralSalt := bytes.NewBufferString("UnidentifiedDelivery")
	ephemeralSalt.Write(ourIdentity.PublicKey.Serialize())
	ephemeralSalt.Write(wrapper.ephemeral.Serialize())

	ephemeralKeys, err := CalculateEphemeralKeys(wrapper.ephemeral, ourIdentity.PrivateKey, ephemeralSalt.Bytes())

	staticKeyBytes, err := s.decryptBytes(
		ephemeralKeys.CipherKey,
		ephemeralKeys.MacKey,
		wrapper.encryptedStatic,
	)
	if err != nil {
		return nil, err
	}

	staticKey := NewECPublicKey(staticKeyBytes[1:33])
	staticSalt := bytes.NewBuffer(ephemeralKeys.ChainKey)
	staticSalt.Write(wrapper.encryptedStatic)
	staticKeys, err := s.calculateStaticKeys(
		staticKey,
		ourIdentity.PrivateKey,
		staticSalt.Bytes(),
	)
	if err != nil {
		return nil, err
	}

	messageBytes, err := s.decryptBytes(
		staticKeys.CipherKey,
		staticKeys.MacKey,
		wrapper.encryptedMessage,
	)
	if err != nil {
		return nil, err
	}

	content, err := NewUnidentifiedSenderMessageContent(messageBytes)
	if err != nil {
		return nil, err
	}

	err = s.CertificateValidator.validate(content.senderCertificate, timestamp)
	if err != nil {
		return nil, err
	}

	return s.decryptMessageContent(*content)
}

type UnidentifiedSenderMessageContent struct {
	rType             protobuf.UnidentifiedSenderMessage_Message_Type
	senderCertificate *SenderCertificate
	content           []byte
}

func NewUnidentifiedSenderMessageContent(data []byte) (*UnidentifiedSenderMessageContent, error) {
	message := &protobuf.UnidentifiedSenderMessage_Message{}
	err := proto.Unmarshal(data, message)
	if err != nil {
		return nil, err
	}
	if len(message.Content) == 0 || message.SenderCertificate == nil || message.Type == nil {
		return nil, errors.New("InvalidMetadataMessageError")
	}
	certificate, err := NewSenderCertificate(message.GetSenderCertificate())
	if err != nil {
		return nil, err
	}
	return &UnidentifiedSenderMessageContent{
		rType:             message.GetType(),
		senderCertificate: certificate,
		content:           message.GetContent(),
	}, nil
}

func (s *SealedSessionCipher) decryptMessageContent(message UnidentifiedSenderMessageContent) (*DecryptionResult, error) {
	var msg []byte
	s.RecipientID = message.senderCertificate.SenderE164
	s.DeviceID = message.senderCertificate.SenderDeviceId
	switch message.rType {
	case protobuf.UnidentifiedSenderMessage_Message_PREKEY_MESSAGE:
		whisperMessage, err := LoadPreKeyWhisperMessage(message.content)
		if err != nil {
			return nil, err
		}
		msg, err = s.SessionCipher.SessionDecryptPreKeyWhisperMessage(whisperMessage)
		if err != nil {
			return nil, err
		}
	case protobuf.UnidentifiedSenderMessage_Message_MESSAGE:
		whisperMessage, err := LoadWhisperMessage(message.content)
		if err != nil {
			return nil, err
		}
		msg, err = s.SessionCipher.SessionDecryptWhisperMessage(whisperMessage)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown message from unidentified sender type")
	}
	session, err := s.SessionStore.LoadSession(message.senderCertificate.SenderUuid, message.senderCertificate.SenderDeviceId)
	if err != nil {
		return nil, err
	}

	return &DecryptionResult{
		PaddedMessage: msg,
		Version:       session.sessionState.getSessionVersion(),
		SenderE164:    message.senderCertificate.SenderE164,
		SenderUuid:    message.senderCertificate.SenderUuid,
		DeviceId:      message.senderCertificate.SenderDeviceId,
	}, nil
}

// ProvisioningCipher
func ProvisioningCipher(pm *protobuf.ProvisionMessage, theirPublicKey ECPublicKey) ([]byte, error) {
	ourKeyPair := GenerateIdentityKeyPair()

	version := []byte{0x01}
	derivedSecret, err := calculateKeysAndDerived(theirPublicKey, ourKeyPair.PrivateKey, nil, []byte("TextSecure Provisioning Message"), 64)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	aesKey := derivedSecret[:32]
	macKey := derivedSecret[32:]
	message, err := proto.Marshal(pm)
	if err != nil {
		return nil, err
	}

	ciphertext, err := crypto.AesEncrypt(aesKey, message)
	if err != nil {
		return nil, err
	}

	m := hmac.New(sha256.New, macKey)
	m.Write(append(version[:], ciphertext[:]...))
	mac := m.Sum(nil)
	body := []byte{}
	body = append(body, version[:]...)
	body = append(body, ciphertext[:]...)
	body = append(body, mac[:]...)

	pe := &protobuf.ProvisionEnvelope{
		PublicKey: ourKeyPair.PublicKey.Serialize(),
		Body:      body,
	}

	return proto.Marshal(pe)
}
