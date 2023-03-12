package constant

const (
	SERVICE_REFLECTOR_HOST = "europe-west1-signal-cdn-reflector.cloudfunctions.net"
	SIGNAL_SERVICE_URL     = "https://coming-server-v2.coming.chat"
	SIGNAL_CDN_URL         = "https://aws-cdn.coming-chat.io"
	SIGNAL_CDN2_URL        = "https://google-cdn.coming.chat"
	DIRECTORY_URL          = "https://api.directory.coming.org"
	STORAGE_URL            = "https://coming-storage-service.coming.chat"

	CreateAccountPath = "/v1/accounts/%s/%s?client=%s"
	// CREATE_ACCOUNT_SMS_PATH   = "/v1/accounts/sms/code/%s?client=%s";
	CREATE_ACCOUNT_VOICE_PATH = "/v1/accounts/voice/code/%s"
	VERIFY_ACCOUNT_CODE_PATH  = "/v1/accounts/code/%s"
	RegisterUPSAccountPath    = "/v1/accounts/ups/"
	TURN_SERVER_INFO          = "/v1/accounts/turn"
	SET_ACCOUNT_ATTRIBUTES    = "/v1/accounts/attributes/"
	PIN_PATH                  = "/v1/accounts/pin/"
	REGISTRATION_LOCK_PATH    = "/v1/accounts/registration_lock"
	REQUEST_PUSH_CHALLENGE    = "/v1/accounts/fcm/preauth/%s/%s"
	WHO_AM_I                  = "/v1/accounts/whoami"
	SET_USERNAME_PATH         = "/v1/accounts/username/%s"
	DELETE_USERNAME_PATH      = "/v1/accounts/username"
	DELETE_ACCOUNT_PATH       = "/v1/accounts/me"
	CID_REGISTER              = "/v1/accounts/v2/cid/cidRegister?signature=%s&transfer=%s"
	LOGIN_PRE_MSG             = "/v1/accounts/login/pre/message"
	LOGIN_GET_CIDS            = "/v1/accounts/login/getAllCids?page=%d&size=%d"
	ALL_CID_LOGIN             = "/v1/accounts/allCid/login?cid=%s&transfer=%s"

	attachmentPath           = "/v2/attachments/form/upload"
	ATTACHMENT_DOWNLOAD_PATH = "/v2/attachments/"

	PrekeyMetadataPath = "/v2/keys/"
	PrekeyPath         = "/v2/keys/%s"
	PrekeyDevicePath   = "/v2/keys/%s/%s"
	signedPrekeyPath   = "/v2/keys/signed"

	ProvisioningCodePath    = "/v1/devices/provisioning/code"
	ProvisioningMessagePath = "/v1/provisioning/%s"
	DevicePath              = "/v1/devices/%s"

	DIRECTORY_TOKENS_PATH   = "/v1/directory/tokens"
	DIRECTORY_VERIFY_PATH   = "/v1/directory/%s"
	DIRECTORY_AUTH_PATH     = "/v1/directory/auth"
	DIRECTORY_FEEDBACK_PATH = "/v1/directory/feedback-v3/%s"

	MESSAGE_PATH            = "/v1/messages/%s"
	acknowledgeMessagePath  = "/v1/messages/%s/%d"
	receiptPath             = "/v1/receipt/%s/%d"
	SENDER_ACK_MESSAGE_PATH = "/v1/messages/%s/%d"
	UUID_ACK_MESSAGE_PATH   = "/v1/messages/uuid/%s"
	ATTACHMENT_V2_PATH      = "/v2/attachments/form/upload"
	ATTACHMENT_V3_PATH      = "/v3/attachments/form/upload"

	PROFILE_PATH          = "/v1/profile/%s"
	PROFILE_USERNAME_PATH = "/v1/profile/username/%s"

	SENDER_CERTIFICATE_PATH         = "/v1/certificate/delivery"
	SENDER_CERTIFICATE_NO_E164_PATH = "/v1/certificate/delivery?includeE164=false"

	KBS_AUTH_PATH = "/v1/backup/auth"

	ATTACHMENT_KEY_DOWNLOAD_PATH = "/attachments/%s"
	ATTACHMENT_ID_DOWNLOAD_PATH  = "/attachments/%d"
	ATTACHMENT_UPLOAD_PATH       = "/attachments/"
	AVATAR_UPLOAD_PATH           = ""

	STICKER_MANIFEST_PATH = "/stickers/%s/manifest.proto"
	STICKER_PATH          = "/stickers/%s/full/%d"

	GROUPSV2_CREDENTIAL     = "/v1/certificate/group/%d/%d"
	GROUPSV2_GROUP          = "/v1/groups/"
	GROUPSV2_GROUP_PASSWORD = "/v1/groups/?inviteLinkPassword=%s"
	GROUPSV2_GROUP_CHANGES  = "/v1/groups/logs/%s"
	GROUPSV2_AVATAR_REQUEST = "/v1/groups/avatar/form"
	GROUPSV2_GROUP_JOIN     = "/v1/groups/join/%s"
	GROUPSV2_TOKEN          = "/v1/groups/token"

	ATTESTATION_REQUEST = "/v1/attestation/%s"
	DISCOVERY_REQUEST   = "/v1/discovery/%s"

	SERVER_DELIVERED_TIMESTAMP_HEADER = "X-Signal-Timestamp"
	CDS_MRENCLAVE                     = "c98e00a4e3ff977a56afefe7362a27e4961e4f19e211febfbb19b897e6b80b15"

	CONTACT_DISCOVERY = "/v1/discovery/%s"
)
