package appproto

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"math/rand"
	"time"
	ioscomm "wechatwebapi/comm"

	"github.com/golang/protobuf/proto"

	"wechatwebapi/wechatandroid/comm"
	"wechatwebapi/wechatandroid/mmproto"
)

type SecManualAuth struct {
	uri        string
	cmdid      uint32
	accoutInfo *AccountInfo
}

func (s *SecManualAuth) GetUri() string {
	return "/cgi-bin/micromsg-bin/secmanualauth"
}

func (s *SecManualAuth) GetCmdId() uint32 {
	return 0xfc
}

func (s *SecManualAuth) GetFuncId() uint32 {
	return 0
}

func (s *SecManualAuth) SetAccountInfo(accountInfo *AccountInfo) {
	s.accoutInfo = accountInfo
}

func (s *SecManualAuth) GetSoftType() string {

	softType := "<softtype><lctmoc>"
	softType += fmt.Sprintf("%d", s.accoutInfo.AllowLocation)
	softType += "</lctmoc><level>"
	softType += fmt.Sprintf("%d", s.accoutInfo.IsRoot)
	softType += "</level><k1>"
	softType += s.accoutInfo.CPUDescription
	softType += "</k1><k2>"
	softType += s.accoutInfo.RadioVerion
	softType += "</k2><k3>"
	softType += s.accoutInfo.RoBuildVersionRelease
	softType += "</k3><k4>"
	softType += s.accoutInfo.Imei
	softType += "</k4><k5>"
	softType += s.accoutInfo.SubscriberID
	softType += "</k5><k6>"
	softType += s.accoutInfo.SimSerialNumber
	softType += "</k6><k7>"
	softType += s.accoutInfo.AndriodID
	softType += "</k7><k8>"
	softType += s.accoutInfo.SerialID
	softType += "</k8><k9>"
	softType += s.accoutInfo.AndroidOsBuildModel
	softType += "</k9><k10>"
	softType += fmt.Sprintf("%d", s.accoutInfo.CPUCount)
	softType += "</k10><k11>"
	softType += s.accoutInfo.Hardware
	softType += "</k11><k12>"
	softType += s.accoutInfo.Revision
	softType += "</k12><k13>"
	softType += s.accoutInfo.Serial
	softType += "</k13><k14>"
	softType += s.accoutInfo.Ssid
	softType += "</k14><k15>"
	softType += s.accoutInfo.BlueToothAddress
	softType += "</k15><k16>"
	softType += s.accoutInfo.Features
	softType += "</k16><k18>"
	softType += s.accoutInfo.PackageSign
	softType += "</k18><k21>"
	softType += s.accoutInfo.WifiName
	softType += "</k21><k22>"
	softType += s.accoutInfo.SimOperatorName
	softType += "</k22><k24>"
	softType += s.accoutInfo.Bssid
	softType += "</k24><k26>"
	softType += fmt.Sprintf("%d", s.accoutInfo.IsDebug)
	softType += "</k26><k30>"
	softType += s.accoutInfo.WifiFullName
	softType += "</k30><k33>"
	softType += s.accoutInfo.PackageName
	softType += "</k33><k34>"
	softType += s.accoutInfo.FingerPrint
	softType += "</k34><k35>"
	softType += s.accoutInfo.AndroidOsBuildBoard
	softType += "</k35><k36>"
	softType += s.accoutInfo.AndroidOsBuildBootLoader
	softType += "</k36><k37>"
	softType += s.accoutInfo.AndroidOsBuildBRAND
	softType += "</k37><k38>"
	softType += s.accoutInfo.AndroidOsBuildDEVICE
	softType += "</k38><k39>"
	softType += s.accoutInfo.AndroidOsBuildHARDWARE
	softType += "</k39><k40>"
	softType += s.accoutInfo.AndroidOsBuildPRODUCT
	softType += "</k40><k41>"
	softType += fmt.Sprintf("%d", s.accoutInfo.IsQemu)
	softType += "</k41><k42>"
	softType += s.accoutInfo.RoProductManufacturer
	//43 "89884a87498ef44f" setting
	//44 -> 0
	softType += "</k42><k43>null</k43><k44>0</k44><k45>"
	softType += s.accoutInfo.PhoneNumber
	softType += "</k45><k46>"
	softType += s.accoutInfo.CashDBOpenSuccess
	softType += "</k46><k47>"
	softType += s.accoutInfo.NetType
	softType += "</k47><k48>"
	softType += s.accoutInfo.Imei
	softType += "</k48><k49>"
	softType += s.accoutInfo.DataDirectory
	softType += "</k49><k52>"
	softType += fmt.Sprintf("%d", s.accoutInfo.IsRePack)
	softType += "</k52><k53>"
	softType += fmt.Sprintf("%d", s.accoutInfo.RecentTasks)
	softType += "</k53><k57>"
	softType += fmt.Sprintf("%d", s.accoutInfo.PackageBuildNumber)
	//58 apkseccode
	softType += "</k57><k58></k58><k59>"
	softType += fmt.Sprintf("%d", s.accoutInfo.XMLInfoType)
	softType += "</k59><k60>"
	softType += s.accoutInfo.FeatureID
	//61 true
	softType += "</k60><k61>true</k61><k62>"
	softType += s.accoutInfo.SoterID
	softType += "</k62><k63>"
	softType += string(s.accoutInfo.GetDeviceId())
	softType += "</k63><k64>"
	softType += comm.GenUUID()
	softType += "</k64><k65>"
	softType += s.accoutInfo.OAID
	softType += "</k65></softtype>"
	return softType
}

func (s *SecManualAuth) GetClientSeqID() string {
	return fmt.Sprintf("%s_%d", s.accoutInfo.GetDeviceId(), (time.Now().UnixNano() / 1e6))
}

func (s *SecManualAuth) GetDeviceType() string {
	return "<deviceinfo><MANUFACTURER name=\"LGE\"><MODEL name=\"Nexus 5X\"><VERSION_RELEASE name=\"8.1.0\"><VERSION_INCREMENTAL name=\"5038062\"><DISPLAY name=\"OPM7.181105.004\"></DISPLAY></VERSION_INCREMENTAL></VERSION_RELEASE></MODEL></MANUFACTURER></deviceinfo>"
}

func (s *SecManualAuth) ToBuffer() []byte {

	devID := make([]byte, 16)
	copy(devID, s.accoutInfo.GetDeviceId())
	devID[15] = 0

	//
	passwordhash := md5.Sum([]byte(s.accoutInfo.GetPassWord()))

	//pub
	pub, priv := comm.Gen713Key()
	s.accoutInfo.ClientPub = pub
	s.accoutInfo.ClientPriv = priv

	//ccd
	ccd1 := s.GetCCD1()
	ccd1PB, _ := proto.Marshal(ccd1)

	ccd2 := s.GetCCD2()
	ccd2PB, _ := proto.Marshal(ccd2)

	ccd3 := s.GetCCD3()
	ccd3PB, _ := proto.Marshal(ccd3)

	devicetoken := s.GetDeviceToken()
	dtPB, _ := proto.Marshal(devicetoken)

	spamdatabody := &mmproto.SpamDataBody{
		Ccd1: &mmproto.SpamDataSubBody{
			Ilen:   proto.Uint32(uint32(len(ccd1PB))),
			Ztdata: ccd1,
		},
		Ccd2: &mmproto.SpamDataSubBody{
			Ilen:   proto.Uint32(uint32(len(ccd2PB))),
			Ztdata: ccd2,
		},
		Ccd3: &mmproto.SpamDataSubBody{
			Ilen:   proto.Uint32(uint32(len(ccd3PB))),
			Ztdata: ccd3,
		},
		Dt: &mmproto.DeviceTokenBody{
			Ilen:        proto.Uint32(uint32(len(dtPB))),
			DeviceToken: devicetoken,
		},
	}

	spamdatabodyPB, _ := proto.Marshal(spamdatabody)
	//组包

	secmanualauth := &mmproto.ManualAuthRequest{
		RsaReqData: &mmproto.ManualAuthRsaReqData{
			RandomEncryKey: &mmproto.SKBuiltinBuffert{
				ILen:   proto.Uint32(16),
				Buffer: comm.RandBytes(16),
			},
			CliPubECDHKey: &mmproto.ECDHKey{
				Nid: proto.Int32(713),
				Key: &mmproto.SKBuiltinBuffert{
					ILen:   proto.Uint32(uint32(len(pub))),
					Buffer: pub,
				},
			},
			UserName: &s.accoutInfo.Username,
			Pwd:      proto.String(hex.EncodeToString(passwordhash[:])),
			Pwd2:     proto.String(hex.EncodeToString(passwordhash[:])),
		},
		AesReqData: &mmproto.ManualAuthAesReqData{
			BaseRequest: &mmproto.BaseRequest{
				SessionKey:    []byte{},
				Uin:           proto.Uint64(0),
				DeviceID:      devID,
				ClientVersion: &s.accoutInfo.Clientversion,
				DeviceType:    &s.accoutInfo.Devicetype,
				Scene:         proto.Uint32(1),
			},
			//BaseReqInfo
			BaseReqInfo: &mmproto.BaseAuthReqInfo{
				WTLoginReqBuff: &mmproto.SKBuiltinBuffert{
					ILen:   proto.Uint32(0),
					Buffer: []byte{},
				},
				WTLoginImgReqInfo: &mmproto.WTLoginImgReqInfo{
					ImgSid:        proto.String(""),
					ImgCode:       proto.String(""),
					ImgEncryptKey: proto.String(""),
					KSid: &mmproto.SKBuiltinBuffert{
						ILen:   proto.Uint32(0),
						Buffer: []byte{},
					},
				},
				WxVerifyCodeReqInfo: &mmproto.WxVerifyCodeReqInfo{
					VerifySignature: proto.String(""),
					VerifyContent:   proto.String(""),
				},
				CliDBEncryptKey: &mmproto.SKBuiltinBuffert{
					ILen:   proto.Uint32(0),
					Buffer: []byte{},
				},
				CliDBEncryptInfo: &mmproto.SKBuiltinBuffert{
					ILen:   proto.Uint32(0),
					Buffer: []byte{},
				},
				AuthReqFlag: proto.Uint32(0),
				AuthTicket:  nil,
			},
			////
			Imei:         &s.accoutInfo.Imei,
			SoftType:     proto.String(s.GetSoftType()),
			BuiltinIPSeq: proto.Uint32(0),
			ClientSeqID:  proto.String(s.GetClientSeqID()),
			Signature:    proto.String(s.accoutInfo.PackageSign),
			DeviceName:   proto.String(s.accoutInfo.RoProductManufacturer + "-" + s.accoutInfo.AndroidOsBuildModel),
			DeviceType:   proto.String(s.GetDeviceType()),
			Language:     proto.String("zh_CN"),
			TimeZone:     proto.String("8.00"),
			Channel:      proto.Int32(0),
			TimeStamp:    proto.Uint32(0),
			DeviceBrand:  proto.String(s.accoutInfo.AndroidOsBuildBRAND),
			DeviceModel:  proto.String(s.accoutInfo.AndroidOsBuildModel + s.accoutInfo.Arch),
			OSType:       proto.String(s.accoutInfo.Devicetype),
			RealCountry:  proto.String(""),
			InputType:    proto.Uint32(2),
			SpamData: &mmproto.SpamData{
				Totallen:     proto.Uint32(uint32(len(spamdatabodyPB))),
				SpamDataBody: spamdatabody,
			},
		},
	}

	pb, _ := proto.Marshal(secmanualauth)
	return pb
}

func (s *SecManualAuth) GetCCD1() *mmproto.ZTData {

	curtime := uint64(time.Now().UnixNano() / 1e6)
	contentlen := len(s.accoutInfo.Username)

	var ct []uint64
	ut := curtime
	for i := 0; i < contentlen; i++ {
		ut += uint64(rand.Intn(10000))
		ct = append(ct, ut)
	}
	ccd := &mmproto.Ccd1{
		StartTime: &curtime,
		CheckTime: &curtime,
		Count:     proto.Uint32(uint32(contentlen)),
		EndTime:   ct,
	}

	pb, _ := proto.Marshal(ccd)

	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(pb)
	w.Close()

	zt := new(comm.ZT)
	zt.Init()
	encData := zt.Encrypt(b.Bytes())

	Ztdata := &mmproto.ZTData{
		Version:   proto.String("00000003\x00"),
		Encrypted: proto.Uint32(1),
		Data:      encData,
		TimeStamp: proto.Uint32(uint32(time.Now().Unix())),
		Optype:    proto.Uint32(5),
		Uin:       proto.Uint32(0),
	}

	return Ztdata
}

func (s *SecManualAuth) GetCCD2() *mmproto.ZTData {

	curtime := uint32(time.Now().Unix())
	curNanoTime := uint64(time.Now().UnixNano())

	ccd := &mmproto.Ccd2{
		Checkid:   proto.String("<LoginByID>"),
		StartTime: &curtime,
		CheckTime: &curtime,
		Count1:    proto.Uint32(0),
		Count2:    proto.Uint32(1),
		Count3:    proto.Uint32(0),
		Const1:    proto.Uint64(384214787666497617),
		Const2:    &curNanoTime,
		Const3:    &curNanoTime,
		Const4:    &curNanoTime,
		Const5:    &curNanoTime,
		Const6:    proto.Uint64(384002236977512448),
	}

	pb, _ := proto.Marshal(ccd)

	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(pb)
	w.Close()

	zt := new(comm.ZT)
	zt.Init()
	encData := zt.Encrypt(b.Bytes())

	Ztdata := &mmproto.ZTData{
		Version:   proto.String("00000003\x00"),
		Encrypted: proto.Uint32(1),
		Data:      encData,
		TimeStamp: proto.Uint32(uint32(time.Now().Unix())),
		Optype:    proto.Uint32(5),
		Uin:       proto.Uint32(0),
	}

	return Ztdata
}

func (s *SecManualAuth) GetCCD3() *mmproto.ZTData {

	curtime := uint32(time.Now().Unix())

	ccd3body := &mmproto.Ccd3Body{
		Loc:                  proto.Uint32(s.accoutInfo.AllowLocation),
		Root:                 proto.Uint32(s.accoutInfo.IsRoot),
		Debug:                proto.Uint32(s.accoutInfo.IsDebug),
		PackageSign:          proto.String(s.accoutInfo.PackageSign),
		RadioVersion:         proto.String(s.accoutInfo.RadioVerion),
		BuildVersion:         proto.String(s.accoutInfo.RoBuildVersionRelease),
		DeviceId:             proto.String(s.accoutInfo.Imei),
		AndroidId:            proto.String(s.accoutInfo.AndriodID),
		SerialId:             proto.String(s.accoutInfo.SerialID),
		Model:                proto.String(s.accoutInfo.AndroidOsBuildModel),
		CpuCount:             proto.Uint32(s.accoutInfo.CPUCount),
		CpuBrand:             proto.String(s.accoutInfo.Hardware),
		CpuExt:               proto.String(s.accoutInfo.Features),
		WlanAddress:          proto.String(s.accoutInfo.WLanAddress),
		Ssid:                 proto.String(s.accoutInfo.Ssid),
		Bssid:                proto.String(s.accoutInfo.Bssid),
		SimOperator:          proto.String(s.accoutInfo.SimOperatorName),
		WifiName:             proto.String(s.accoutInfo.WifiFullName),
		BuildFP:              proto.String(s.accoutInfo.FingerPrint),
		BuildBoard:           proto.String(s.accoutInfo.AndroidOsBuildBoard),
		BuildBootLoader:      proto.String(s.accoutInfo.AndroidOsBuildBootLoader),
		BuildBrand:           proto.String(s.accoutInfo.AndroidOsBuildBRAND),
		BuildDevice:          proto.String(s.accoutInfo.AndroidOsBuildDEVICE),
		GsmSimOperatorNumber: proto.String(s.accoutInfo.SimSerialNumber),
		SoterId:              proto.String(s.accoutInfo.SoterID),
		KernelReleaseNumber:  proto.String(s.accoutInfo.KernelReleaseNumber),
		UsbState:             proto.Uint32(0),
		Sign:                 proto.String(s.accoutInfo.PackageSign),
		PackageFlag:          proto.Uint32(14),
		AccessFlag:           proto.Uint32(364604),
		Unkonwn:              proto.Uint32(3),
		TbVersionCrc:         proto.Uint32(553983350),
		SfMD5:                proto.String("d001b450158a85142c953011c66d531d"),
		SfArmMD5:             proto.String("bf7f84d081f1dffd587803c233d4e235"),
		SfArm64MD5:           proto.String("85801b3939f277ad31c9f89edd9dd008"),
		SbMD5:                proto.String("683e7beb7a44017ca2e686e3acedfb9f"),
		SoterId2:             proto.String(""),
		WidevineDeviceID:     proto.String(comm.AndriodDeviceID(s.accoutInfo.Deviceid_str)),
		FSID:                 proto.String(comm.AndriodFSID(s.accoutInfo.Deviceid_str)),
		Oaid:                 proto.String(s.accoutInfo.OAID),
		TimeCheck:            proto.Uint32(0),
		NanoTime:             proto.Uint32(455583),
		Refreshtime:          proto.Uint32(s.accoutInfo.RefreshTime),
		SoftConfig:           s.accoutInfo.SoftConfig,
		SoftData:             s.accoutInfo.SoftData,
	}

	pb, _ := proto.Marshal(ccd3body)

	crc := crc32.ChecksumIEEE(pb)

	ccd3 := &mmproto.Ccd3{
		Crc:       &crc,
		TimeStamp: &curtime,
		Body:      ccd3body,
	}

	pb, _ = proto.Marshal(ccd3)

	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(pb)
	w.Close()

	zt := new(comm.ZT)
	zt.Init()
	encData := zt.Encrypt(b.Bytes())

	Ztdata := &mmproto.ZTData{
		Version:   proto.String("00000003\x00"),
		Encrypted: proto.Uint32(1),
		Data:      encData,
		TimeStamp: &curtime,
		Optype:    proto.Uint32(5),
		Uin:       proto.Uint32(0),
	}
	return Ztdata
}

func (s *SecManualAuth) GetDeviceToken() *mmproto.DeviceToken {

	curtime := uint32(time.Now().Unix())

	return &mmproto.DeviceToken{
		Version:   proto.String(""),
		Encrypted: proto.Uint32(1),
		Data: &mmproto.SKBuiltinStringt{
			String_: &s.accoutInfo.Devicetoken,
		},
		TimeStamp: &curtime,
		Optype:    proto.Uint32(2),
		Uin:       proto.Uint32(0),
	}
}

func (s *SecManualAuth) OnResponse(loginRes mmproto.UnifyAuthResponse, LoginData ioscomm.LoginData) error {

	//calc session key
	ecdhkey := comm.Do713Ecdh(loginRes.GetAuthSectResp().GetSvrPubECDHKey().GetKey().GetBuffer(), s.accoutInfo.ClientPriv)
	LoginData.Loginecdhkey = ecdhkey
	s.accoutInfo.AuthEcdhKey = ecdhkey
	s.accoutInfo.Sessionkey = comm.DecryptAES(loginRes.GetAuthSectResp().GetSessionKey().GetBuffer(), ecdhkey)
	LoginData.Uin = loginRes.GetAuthSectResp().GetUin()
	LoginData.Wxid = loginRes.GetAcctSectResp().GetUserName()
	LoginData.Alais = loginRes.GetAcctSectResp().GetAlias()
	LoginData.Mobile = loginRes.GetAcctSectResp().GetBindMobile()
	LoginData.NickName = loginRes.GetAcctSectResp().GetNickName()
	LoginData.Sessionkey = s.accoutInfo.Sessionkey
	LoginData.Sessionkey_2 = loginRes.GetAuthSectResp().GetSessionKey().GetBuffer()
	LoginData.Autoauthkey = loginRes.GetAuthSectResp().GetAutoAuthKey().GetBuffer()
	LoginData.Autoauthkeylen = int32(loginRes.GetAuthSectResp().GetAutoAuthKey().GetILen())
	LoginData.Serversessionkey = loginRes.GetAuthSectResp().GetServerSessionKey().GetBuffer()
	LoginData.Clientsessionkey = loginRes.GetAuthSectResp().GetClientSessionKey().GetBuffer()

	err := ioscomm.CreateLoginData(LoginData,LoginData.Wxid,0)
	if err != nil {
		return err
	}

	return nil
}
