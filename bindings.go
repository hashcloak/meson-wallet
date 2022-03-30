package main

import "C"

import (
	"unsafe"

	client "github.com/hashcloak/Meson-client"
	"github.com/hashcloak/Meson-client/config"
	"github.com/katzenpost/client/utils"
	"github.com/katzenpost/core/crypto/ecdh"
)

var goConfig *config.Config
var goClient *client.Client
var goSession *client.Session
var goLinkKey *ecdh.PrivateKey
var goService *utils.ServiceDescriptor

//export Register
func Register(configFile *C.char) {
	gConfigFile := C.GoString(configFile)
	cfg, err := config.LoadFile(gConfigFile)
	if err != nil {
		panic(err)
	}
	_ = cfg.UpdateTrust()
	_ = cfg.SaveConfig(gConfigFile)
	goLinkKey = client.AutoRegisterRandomClient(cfg)
	goConfig = cfg
}

//export NewClient
func NewClient(service *C.char) {
	c, err := client.NewFromConfig(goConfig, C.GoString(service))
	if err != nil {
		panic(err)
	}
	goClient = c
}

//export NewSession
func NewSession() {
	s, err := goClient.NewSession(goLinkKey)
	if err != nil {
		panic(err)
	}
	goSession = s
}

//export GetService
func GetService(service *C.char) {
	serviceDesc, err := goSession.GetService(C.GoString(service))
	if err != nil {
		panic(err)
	}
	goService = serviceDesc
}

//export BlockingSendUnreliableMessage
func BlockingSendUnreliableMessage(messagePtr unsafe.Pointer, messageLen C.int) unsafe.Pointer {
	message := C.GoBytes(messagePtr, messageLen)
	resp, err := goSession.BlockingSendUnreliableMessage(goService.Name, goService.Provider, message)
	if err != nil {
		panic(err)
	}
	return C.CBytes(resp)
}

//export Shutdown
func Shutdown() {
	goClient.Shutdown()
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
