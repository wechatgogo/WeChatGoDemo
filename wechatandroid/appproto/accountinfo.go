package appproto

type AccountInfo struct {
	Username      string
	Password      string
	Deviceid      []byte
	Deviceid_str  string
	Clientversion int32
	Devicetype    string
	Devicetoken   string
	///softtype
	AllowLocation            uint32
	IsDebug                  uint32
	IsRoot                   uint32
	RadioVerion              string // M8994F-2.6.42.5.03
	RoBuildVersionRelease    string // 8.1.0
	Imei                     string // 353627078088849
	AndriodID                string // 06a78780bc297bbd
	SerialID                 string // 01c5cded725f4db6
	AndroidOsBuildModel      string // "Nexus 5X"
	CPUCount                 uint32 // 6
	Hardware                 string //Qualcomm Technologies, Inc MSM8992
	Revision                 string //""
	Serial                   string //""
	Ssid                     string //02:00:00:00:00:00 "<unknown ssid>"
	Bssid                    string //02:00:00:00:00:00
	Features                 string //half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt evtstrm aes pmull sha1 sha2 crc32
	PackageSign              string //18c867f0717aa67b2ab7347505ba07ed
	WifiName                 string //Chinanet-2.4G-103
	WifiFullName             string //&quot;Chinanet-2.4G-103&quot;
	FingerPrint              string //google/bullhead/bullhead:8.1.0/OPM7.181105.004/5038062:user/release-keys
	AndroidOsBuildBoard      string //bullhead
	AndroidOsBuildBootLoader string //BHZ32c
	AndroidOsBuildBRAND      string //google
	AndroidOsBuildDEVICE     string //bullhead
	AndroidOsBuildHARDWARE   string //bullhead
	AndroidOsBuildPRODUCT    string //bullhead
	RoProductManufacturer    string //LGE
	PhoneNumber              string //""
	NetType                  string //wifi
	RecentTasks              uint32 //0
	PackageBuildNumber       uint32 //1600
	XMLInfoType              uint32 //3
	FeatureID                string //""
	SoterID                  string //""
	OAID                     string //""
	IsRePack                 uint32 //0
	DataDirectory            string ///data/user/0/com.tencent.mm/
	PackageName              string //com.tencent.mm
	IsQemu                   uint32 // 0
	SimOperatorName          string //""
	CashDBOpenSuccess        string //"" or "1"
	CPUDescription           string //"0 "
	SubscriberID             string //""
	SimSerialNumber          string //""
	BlueToothAddress         string //""
	KernelReleaseNumber      string //3.10.73-g0a05126d69c9
	WLanAddress              string //"00:a0:07:86:17:18"
	Arch                     string // armeabi-v7a

	//keys
	ClientPub   []byte
	ClientPriv  []byte
	Sessionkey  []byte
	AuthEcdhKey []byte
	UiCryptin   uint32
	Cookies     []byte

	//authUserInfo
	WXID     string
	NickName string

	//softConfit
	RefreshTime uint32
	SoftConfig  []byte
	SoftData    []byte
}

func (a *AccountInfo) GetUserName() string {
	return a.Username
}

func (a *AccountInfo) GetPassWord() string {
	return a.Password
}

func (a *AccountInfo) GetDeviceId() []byte {
	return a.Deviceid
}

func (a *AccountInfo) GetSessKey() []byte {
	return a.Sessionkey
}

func (a *AccountInfo) SetUserName(userName string) {
	a.Username = userName
}

func (a *AccountInfo) SetPassWord(passWord string) {
	a.Password = passWord
}

func (a *AccountInfo) SetDeviceId(deviceId []byte) {
	a.Deviceid = deviceId
}

func (a *AccountInfo) SetSessKey(sessKey []byte) {
	a.Sessionkey = sessKey
}
