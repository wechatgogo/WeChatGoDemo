package appproto

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"wechatwebapi/wechatandroid/comm"
	"wechatwebapi/wechatandroid/mmproto"
	"time"

	"github.com/golang/protobuf/proto"
)

type TrustInfoInit struct {
	uri   string
	cmdid uint32

	accoutInfo *AccountInfo
}

func (t *TrustInfoInit) SetAccountInfo(accountInfo *AccountInfo) {
	t.accoutInfo = accountInfo
}

type VMFunc func(input [][]byte, dst, srt byte)

func VMFunc_Exchange(input [][]byte, dst, src byte) {
	input[dst], input[src] = input[src], input[dst]
}

func VMFunc_Xor(input [][]byte, dst, src byte) {

	size := len(input[dst])
	for i := 0; i < size; i++ {
		input[dst][i] ^= input[src][i]
	}
}

func (t *TrustInfoInit) GetUri() string {
	return "/cgi-bin/micromsg-bin/fpinitnl"
}

func (t *TrustInfoInit) GetCmdid() uint32 {
	return 3789
}

func (t *TrustInfoInit) ToBuffer() []byte {

	td := &mmproto.TrustReq{
		Td: &mmproto.TrustData{
			Tdi: []*mmproto.TrustDeviceInfo{
				{Key: proto.String("IMEI"), Val: proto.String(comm.AndriodImei(t.accoutInfo.Deviceid_str))},
				{Key: proto.String("AndroidID"), Val: proto.String(comm.AndriodID(t.accoutInfo.Deviceid_str))},
				{Key: proto.String("PhoneSerial"), Val: proto.String(comm.AndriodSerial(t.accoutInfo.Deviceid_str))},
				{Key: proto.String("cid"), Val: proto.String("")},
				{Key: proto.String("WidevineDeviceID"), Val: proto.String(comm.AndriodWidevineDeviceID(t.accoutInfo.Deviceid_str))},
				{Key: proto.String("WidevineProvisionID"), Val: proto.String(comm.AndriodWidevineProvisionID(t.accoutInfo.Deviceid_str))},
				{Key: proto.String("GSFID"), Val: proto.String("")},
				{Key: proto.String("SoterID"), Val: proto.String("")},
				{Key: proto.String("SoterUid"), Val: proto.String("")},
				{Key: proto.String("FSID"), Val: proto.String(comm.AndriodFSID(t.accoutInfo.Deviceid_str))},
				{Key: proto.String("BootID"), Val: proto.String("")},
				{Key: proto.String("IMSI"), Val: proto.String("")},
				{Key: proto.String("PhoneNum"), Val: proto.String("")},
				{Key: proto.String("WeChatInstallTime"), Val: proto.String("1515061151")},
				{Key: proto.String("PhoneModel"), Val: proto.String("Nexus 5X")},
				{Key: proto.String("BuildBoard"), Val: proto.String("bullhead")},
				{Key: proto.String("BuildBootloader"), Val: proto.String("BHZ32c")},
				{Key: proto.String("SystemBuildDate"), Val: proto.String("Fri Sep 28 23:37:27 UTC 2018")},
				{Key: proto.String("SystemBuildDateUTC"), Val: proto.String("1538177847")},
				{Key: proto.String("BuildFP"), Val: proto.String("google/bullhead/bullhead:8.1.0/OPM7.181105.004/5038062:user/release-keys")},
				{Key: proto.String("BuildID"), Val: proto.String("OPM7.181105.004")},
				{Key: proto.String("BuildBrand"), Val: proto.String("google")},
				{Key: proto.String("BuildDevice"), Val: proto.String("bullhead")},
				{Key: proto.String("BuildProduct"), Val: proto.String("bullhead")},
				{Key: proto.String("Manufacturer"), Val: proto.String("LGE")},
				{Key: proto.String("RadioVersion"), Val: proto.String("M8994F-2.6.42.5.03")},
				{Key: proto.String("AndroidVersion"), Val: proto.String("8.1.0")},
				{Key: proto.String("SdkIntVersion"), Val: proto.String("27")},
				{Key: proto.String("ScreenWidth"), Val: proto.String("1080")},
				{Key: proto.String("ScreenHeight"), Val: proto.String("1794")},
				{Key: proto.String("SensorList"), Val: proto.String("BMI160 accelerometer#Bosch#0.004788#1,BMI160 gyroscope#Bosch#0.000533#1,BMM150 magnetometer#Bosch#0.000000#1,BMP280 pressure#Bosch#0.005000#1,BMP280 temperature#Bosch#0.010000#1,RPR0521 Proximity Sensor#Rohm#1.000000#1,RPR0521 Light Sensor#Rohm#10.000000#1,Orientation#Google#1.000000#1,BMI160 Step detector#Bosch#1.000000#1,Significant motion#Google#1.000000#1,Gravity#Google#1.000000#1,Linear Acceleration#Google#1.000000#1,Rotation Vector#Google#1.000000#1,Geomagnetic Rotation Vector#Google#1.000000#1,Game Rotation Vector#Google#1.000000#1,Pickup Gesture#Google#1.000000#1,Tilt Detector#Google#1.000000#1,BMI160 Step counter#Bosch#1.000000#1,BMM150 magnetometer (uncalibrated)#Bosch#0.000000#1,BMI160 gyroscope (uncalibrated)#Bosch#0.000533#1,Sensors Sync#Google#1.000000#1,Double Twist#Google#1.000000#1,Double Tap#Google#1.000000#1,Device Orientation#Google#1.000000#1,BMI160 accelerometer (uncalibrated)#Bosch#0.004788#1")},
				{Key: proto.String("DefaultInputMethod"), Val: proto.String("com.google.android.inputmethod.latin")},
				{Key: proto.String("InputMethodList"), Val: proto.String("Google \345\215\260\345\272\246\350\257\255\351\224\256\347\233\230#com.google.android.apps.inputmethod.hindi,Google \350\257\255\351\237\263\350\276\223\345\205\245#com.google.android.googlequicksearchbox,Google \346\227\245\350\257\255\350\276\223\345\205\245\346\263\225#com.google.android.inputmethod.japanese,Google \351\237\251\350\257\255\350\276\223\345\205\245\346\263\225#com.google.android.inputmethod.korean,Gboard#com.google.android.inputmethod.latin,\350\260\267\346\255\214\346\213\274\351\237\263\350\276\223\345\205\245\346\263\225#com.google.android.inputmethod.pinyin")},
				{Key: proto.String("DeviceID"), Val: proto.String(comm.AndriodDeviceID(t.accoutInfo.Deviceid_str))},
				{Key: proto.String("OAID"), Val: proto.String("")},
			},
		},
	}

	pb, _ := proto.Marshal(td)

	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(pb)
	w.Close()

	zt := new(comm.ZT)
	zt.Init()
	encData := zt.Encrypt(b.Bytes())

	randKey := make([]byte, 16)
	io.ReadFull(rand.Reader, randKey)

	fp := &mmproto.FPFresh{
		BaseReq: &mmproto.BaseRequest{
			SessionKey:    []byte{},
			Uin:           proto.Uint64(0),
			DeviceID:      append([]byte("A0e4a76905e8f67"), 0),
			ClientVersion: proto.Int32(0x27000b32),
			DeviceType:    proto.String("android-27"),
			Scene:         proto.Uint32(0),
		},
		SessKey: randKey,
		Ztdata: &mmproto.ZTData{
			Version:   proto.String("00000003\x00"),
			Encrypted: proto.Uint32(1),
			Data:      encData,
			TimeStamp: proto.Uint32(uint32(time.Now().Unix())),
			Optype:    proto.Uint32(5),
			Uin:       proto.Uint32(0),
		},
	}

	fpPB, _ := proto.Marshal(fp)
	return fpPB
}

func (t *TrustInfoInit) OnResponse(input []byte) {

	tiiResp := &mmproto.TrustResponse{}
	err := proto.Unmarshal(input, tiiResp)
	if err != nil {
		fmt.Println("tii unmarshal faile")
		return
	}

	if tiiResp.GetBaseResponse().GetRet() != 0 {
		fmt.Println(tiiResp.GetBaseResponse().GetErrMsg())
		return
	}


	//var bbb bytes
	bbb, err := json.Marshal(tiiResp.GetTrustResponseData().GetSoftData())
	if err != nil {
		fmt.Println("json err:", err)
	}
	fmt.Println(string(bbb))

	t.accoutInfo.SoftConfig = tiiResp.GetTrustResponseData().GetSoftData().GetSoftData()
	t.accoutInfo.SoftData = tiiResp.GetTrustResponseData().GetSoftData().GetSoftConfig()
	t.accoutInfo.RefreshTime = tiiResp.GetTrustResponseData().GetTimeStamp()

	t.GetDeviceSoftID(
		tiiResp.GetTrustResponseData().GetSoftData().GetSoftConfig(),
		tiiResp.GetTrustResponseData().GetSoftData().GetSoftData(),
	)

}

func (t *TrustInfoInit) GetDeviceSoftID(softConfig, softData []byte) string {

	var GVMFuncs [6]VMFunc
	GVMFuncs[0] = VMFunc_Exchange
	GVMFuncs[1] = VMFunc_Xor
	GVMFuncs[2] = nil
	GVMFuncs[3] = nil
	GVMFuncs[4] = nil
	GVMFuncs[5] = nil

	funcMap := make(map[byte]VMFunc, 6)

	if softData[0] != 0x44 || softData[1] != 0x59 || softData[2] != 0x45 || softData[3] != 1 {
		fmt.Println("DYE FORMAT ERROR")
		return ""
	}

	if softData[4] != 6 {
		fmt.Println("DYE FLAG FAILE")
		return ""
	}

	for i := 0; i < 6; i++ {
		funcMap[softData[8+i]] = GVMFuncs[i]
	}
	endOpcode := softData[13]
	count := len(softConfig) / 8

	vmConfig := make([][]byte, count)

	for j := 0; j < count; j++ {
		vmConfig[j] = softConfig[(j * 8):(j*8 + 8)]
	}

	offset := 0x10

	for {
		opCode := softData[offset]

		if opCode == endOpcode {
			break
		}
		funcMap[opCode](vmConfig, softData[offset+1], softData[offset+2])

		offset += 4
	}

	result := append([]byte{}, vmConfig[0]...)
	result = append(result, vmConfig[1]...)
	result = append(result, vmConfig[2]...)
	result = append(result, vmConfig[3]...)
	fmt.Println(string(result))

	return string(result)

}
