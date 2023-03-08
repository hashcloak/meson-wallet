package main

import "C"

import (
	"unsafe"

	client "github.com/hashcloak/Meson/client"
	"github.com/hashcloak/Meson/client/config"
	"github.com/katzenpost/client/utils"
	"github.com/katzenpost/core/crypto/ecdh"
)

//todo: send the client, session... to rust so it can be reused.
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
func BlockingSendUnreliableMessage(messagePtr unsafe.Pointer, messageLen C.int) (unsafe.Pointer, int32) {
	message := C.GoBytes(messagePtr, messageLen)
	//fmt.Printf("Sending Sphinx packet payload to: %s@%s\n", goService.Name, goService.Provider)
	resp, err := goSession.BlockingSendUnreliableMessage(goService.Name, goService.Provider, message)
	if err != nil {
		panic(err)
	}
	length := int32(len(resp))
	c_resp := C.CBytes(resp[:])
	return c_resp, length //sending the length of the packet for Rust

	// for sending CString
	// str_resp := string(resp[4:])
	// cs_resp := C.CString(str_resp)
}

//export SendUnreliableMessage
func SendUnreliableMessage(messagePtr unsafe.Pointer, messageLen C.int) (unsafe.Pointer, int32) {
	message := C.GoBytes(messagePtr, messageLen)
	//fmt.Printf("Sending Sphinx packet payload to: %s@%s\n", goService.Name, goService.Provider)
	msgID, err := goSession.SendUnreliableMessage(goService.Name, goService.Provider, message)
	if err != nil {
		panic(err)
	}
	length := int32(len(msgID))
	c_resp := C.CBytes(msgID[:])
	return c_resp, length
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
