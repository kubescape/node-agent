package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	logger "github.com/kubescape/go-logger"
)

const (
	RELAVENT_CVES_SERVICE       = "RELAVENT_CVES_SERVICE"
	CONTAINER_PROFILING_SERVICE = "CONTAINER_PROFILING_SERVICE"
)

const (
	EBPF_ENGINE_FALCO  = "falco"
	EBPF_ENGINE_CILIUM = "cilium"
)

var myContainerID string

var sycscallFilterForRelaventCVES []string
var manadatoryConfigurationVars []string
var relaventCVEService bool
var ebpfEngine string

func init() {
	manadatoryConfigurationVars = append(manadatoryConfigurationVars, "myNode")
	relaventCVEService = false
	myContainerID = "111111111111111111"
}

func parseConfigurationFile(configurationFilePath string) error {
	readFile, err := os.Open(configurationFilePath)
	if err != nil {
		return err
	}

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		line := fileScanner.Text()
		confData := strings.Split(line, "=")
		if confData[0] == line {
			log.Printf("ParseConfigurationFile: seperator = is not exist in configuration file line: %s\n", line)
			continue
		}
		if os.Setenv(confData[0], confData[1]) != nil {
			log.Printf("ParseConfigurationFile: fail to set env %s=%s", confData[0], confData[1])
		}
	}
	readFile.Close()
	return nil
}

func validateMandatoryConfigurationn() error {
	for i := range manadatoryConfigurationVars {
		if _, exist := os.LookupEnv(manadatoryConfigurationVars[i]); !exist {
			return fmt.Errorf("validateMandatoryConfigurationn: %s not exist", manadatoryConfigurationVars[i])
		}
	}
	return nil
}

func ebpfEngineConfig() bool {
	val, exist := os.LookupEnv("ebpfEngine")
	if exist {
		if val != EBPF_ENGINE_FALCO && val != EBPF_ENGINE_CILIUM {
			return false
		}
		ebpfEngine = val
	} else {
		ebpfEngine = EBPF_ENGINE_FALCO
	}
	if ebpfEngine != EBPF_ENGINE_FALCO {
		manadatoryConfigurationVars = append(manadatoryConfigurationVars, "kernelObjPath")
		manadatoryConfigurationVars = append(manadatoryConfigurationVars, "snifferEngineLoaderPath")
		sycscallFilterForRelaventCVES = append(sycscallFilterForRelaventCVES, []string{"execve", "execveat", "open", "openat"}...)
	}
	return true
}

func servicesConfig() error {
	serviceExist := false

	val, exist := os.LookupEnv("enableRelaventCVEsService")
	if exist {
		if val == "true" || val == "True" {
			relaventCVEService = true
			serviceExist = true
			logger.L().Info("sneeffer service find relavent CVEs is enabled\n")
		}
	}
	if !serviceExist {
		return fmt.Errorf("no service is configured to use, please look in the configuration file that one of the services mark as true or True")
	}
	return nil
}

func afterConfigurationParserActions() error {
	ebpfEngineConfig()
	return servicesConfig()
}

func ParseConfiguration() error {
	configurationFilePath, exist := os.LookupEnv("SNEEFFER_CONF_FILE_PATH")
	if !exist {
		return fmt.Errorf("env var SNEEFFER_CONF_FILE_PATH is not exist")
	}

	err := parseConfigurationFile(configurationFilePath)
	if err != nil {
		return err
	}

	err = validateMandatoryConfigurationn()
	if err != nil {
		return err
	}

	err = afterConfigurationParserActions()
	if err != nil {
		return err
	}

	return nil
}

func GetSyscallFilter() []string {
	return sycscallFilterForRelaventCVES
}

func IsRelaventCVEServiceEnabled() bool {
	return relaventCVEService
}

func IsFalcoEbpfEngine() bool {
	return ebpfEngine == EBPF_ENGINE_FALCO
}

func SetMyContainerID(ContainerID string) {
	myContainerID = ContainerID
}

func GetMyContainerID() string {
	return myContainerID
}
