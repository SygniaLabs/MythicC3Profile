package c2functions

import (
	"encoding/json"
	"fmt"
	c2structs "github.com/MythicMeta/MythicContainer/c2_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"os"
	"path/filepath"
)

type config struct {
	Instances []instanceConfig `json:"instances"`
}
type instanceConfig struct {
	Port             int               `json:"port"`
	KeyPath          string            `json:"key_path"`
	CertPath         string            `json:"cert_path"`
	Debug            bool              `json:"debug"`
	UseSSL           bool              `json:"use_ssl"`
	PayloadHostPaths map[string]string `json:"payloads"`
}

func getC2JsonConfig() (*config, error) {
	currentConfig := config{}
	if configBytes, err := os.ReadFile(filepath.Join(".", "c3", "c2_code", "config.json")); err != nil {
		return nil, err
	} else if err = json.Unmarshal(configBytes, &currentConfig); err != nil {
		logging.LogError(err, "Failed to unmarshal config bytes")
		return nil, err
	} else {
		return &currentConfig, nil
	}
}
func writeC2JsonConfig(cfg *config) error {
	jsonBytes, err := json.MarshalIndent(*cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(".", "c3", "c2_code", "config.json"), jsonBytes, 644)
}

var C3c2definition = c2structs.C2Profile{
	Name:             "C3",
	Author:           "@lerneroleg",
	Description:      "Integration with C3, uses HTTP Get/Post messages for connectivity between the servers",
	IsP2p:            false,
	IsServerRouted:   true,
	ServerBinaryPath: filepath.Join(".", "c3", "c2_code", "mythic_c3_server"),
	ConfigCheckFunction: func(message c2structs.C2ConfigCheckMessage) c2structs.C2ConfigCheckMessageResponse {
		response := c2structs.C2ConfigCheckMessageResponse{
			Success: true,
			Message: fmt.Sprintf("Called config check\n%v", message),
		}
		if _,ok := message.Parameters["pipename"]; !ok {
			response.Success = false
			response.Error = "Failed to get pipename attribute"
			return response
		}
		return response;		
	},
	OPSECCheckFunction: func(message c2structs.C2OPSECMessage) c2structs.C2OPSECMessageResponse {
		response := c2structs.C2OPSECMessageResponse{
			Success: true,
			Message: fmt.Sprintf("Called opsec check:\n%v", message),
		}
		response.Message = "No immediate issues with configuration"
		return response
	},
	GetIOCFunction: func(message c2structs.C2GetIOCMessage) c2structs.C2GetIOCMessageResponse {
		response := c2structs.C2GetIOCMessageResponse{Success: true}
		getPipe, err := message.GetStringArg("pipename")
		if err != nil {
			response.Success = false
			response.Error = "Failed to get pipename"
			return response
		}

		response.IOCs = append(response.IOCs, c2structs.IOC{
			Type: "pipename",
			IOC:  fmt.Sprintf("%s", getPipe),
		})
		return response
	},
	SampleMessageFunction: func(message c2structs.C2SampleMessageMessage) c2structs.C2SampleMessageResponse {
		response := c2structs.C2SampleMessageResponse{Success: true}
		sampleMessage := "Currently no samples"
		response.Message = sampleMessage
		return response
	},
	HostFileFunction: func(message c2structs.C2HostFileMessage) c2structs.C2HostFileMessageResponse {
		config, err := getC2JsonConfig()
		if err != nil {
			return c2structs.C2HostFileMessageResponse{
				Success: false,
				Error:   err.Error(),
			}
		}
		for i, _ := range config.Instances {
			if config.Instances[i].PayloadHostPaths == nil {
				config.Instances[i].PayloadHostPaths = make(map[string]string)
			}
			config.Instances[i].PayloadHostPaths[message.HostURL] = message.FileUUID
		}
		err = writeC2JsonConfig(config)
		if err != nil {
			return c2structs.C2HostFileMessageResponse{
				Success: false,
				Error:   err.Error(),
			}
		}
		return c2structs.C2HostFileMessageResponse{
			Success: true,
		}
	},
}
var C3c2parameters = []c2structs.C2Parameter{
	{
		Name:          "pipename",
		Description:   "Named Pipe",
		VerifierRegex: `[a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12}`,
		FormatString:  `[a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12}`,
		ParameterType: c2structs.C2_PARAMETER_TYPE_STRING,
		Randomize:     true,
		Required:      true,
	},
	{
		Name:          "killdate",
		Description:   "Kill Date",
		DefaultValue:  30,
		ParameterType: c2structs.C2_PARAMETER_TYPE_DATE,
		Required:      false,
	},
	{
		Name:          "encrypted_exchange_check",
		Description:   "Perform Key Exchange",
		DefaultValue:  true,
		ParameterType: c2structs.C2_PARAMETER_TYPE_BOOLEAN,
		Required:      false,
	},
	{
		Name:          "callback_jitter",
		Description:   "Callback Jitter in percent",
		DefaultValue:  5,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
	{
		Name:          "AESPSK",
		Description:   "Encryption Type",
		DefaultValue:  "aes256_hmac",
		ParameterType: c2structs.C2_PARAMETER_TYPE_CHOOSE_ONE,
		Required:      false,
		IsCryptoType:  true,
		Choices: []string{
			"aes256_hmac",
			"none",
		},
	},
	{
		Name:          "callback_interval",
		Description:   "Callback Interval in seconds",
		DefaultValue:  30,
		ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER,
		Required:      false,
		VerifierRegex: "^[0-9]+$",
	},
}

func Initialize() {
	c2structs.AllC2Data.Get("C3").AddC2Definition(C3c2definition)
	c2structs.AllC2Data.Get("C3").AddParameters(C3c2parameters)
}