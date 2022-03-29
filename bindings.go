package main

import "C"

import (
	"unsafe"

	client "github.com/hashcloak/Meson-client"
	"github.com/hashcloak/Meson-client/config"
	"github.com/katzenpost/client/utils"
	"github.com/katzenpost/core/crypto/ecdh"
)

var myConfig *config.Config
var myClient *client.Client
var mySession *client.Session
var myLinkKey *ecdh.PrivateKey
var myService *utils.ServiceDescriptor

//export Register
func Register(configFile *C.char) {
	gConfigFile := C.GoString(configFile)
	cfg, err := config.LoadFile(gConfigFile)
	if err != nil {
		panic(err)
	}
	_ = cfg.UpdateTrust()
	_ = cfg.SaveConfig(gConfigFile)
	myLinkKey = client.AutoRegisterRandomClient(cfg)
	myConfig = cfg
}

//export NewFromConfig
func NewFromConfig(service *C.char) {
	c, err := client.NewFromConfig(myConfig, C.GoString(service))
	if err != nil {
		panic(err)
	}
	myClient = c
}

//export NewSession
func NewSession() {
	s, err := myClient.NewSession(myLinkKey)
	if err != nil {
		panic(err)
	}
	mySession = s
}

//export GetService
func GetService(service *C.char) {
	serviceDesc, err := mySession.GetService(C.GoString(service))
	if err != nil {
		panic(err)
	}
	myService = serviceDesc
}

//export BlockingSendUnreliableMessage
func BlockingSendUnreliableMessage(messagePtr unsafe.Pointer, messageLen C.int) unsafe.Pointer {
	message := C.GoBytes(messagePtr, messageLen)
	resp, err := mySession.BlockingSendUnreliableMessage(myService.Name, myService.Provider, message)
	if err != nil {
		panic(err)
	}
	return C.CBytes(resp)
}

//export Shutdown
func Shutdown() {
	myClient.Shutdown()
}

//export ValidateReply
func ValidateReply(respPtr unsafe.Pointer, respLen C.int) unsafe.Pointer {
	resp := C.GoBytes(respPtr, respLen)
	payload, err := client.ValidateReply(resp)
	if err != nil {
		panic(err)
	}
	return C.CBytes(payload)
}

func main() {}
