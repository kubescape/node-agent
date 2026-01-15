package hostsensormanager

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	procSysKernelDir = "/proc/sys/kernel"
)

// LinuxKernelVariablesSensor implements the Sensor interface for kernel variables data
type LinuxKernelVariablesSensor struct {
	nodeName string
}

// NewLinuxKernelVariablesSensor creates a new kernel variables sensor
func NewLinuxKernelVariablesSensor(nodeName string) *LinuxKernelVariablesSensor {
	return &LinuxKernelVariablesSensor{
		nodeName: nodeName,
	}
}

// GetKind returns the CRD kind for this sensor
func (s *LinuxKernelVariablesSensor) GetKind() string {
	return "LinuxKernelVariables"
}

// GetPluralKind returns the plural and lowercase form of CRD kind for this sensor
func (s *LinuxKernelVariablesSensor) GetPluralKind() string {
	return "linuxkernelvariables"
}

// Sense collects the kernel variables data from the host
func (s *LinuxKernelVariablesSensor) Sense() (interface{}, error) {
	hProcSysKernelDir := hostPath(procSysKernelDir)
	procDir, err := os.Open(hProcSysKernelDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open procSysKernelDir dir(%s): %w", hProcSysKernelDir, err)
	}
	defer procDir.Close()

	vars, err := s.walkVarsDir(procSysKernelDir, procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to walk kernel variables: %w", err)
	}

	return &LinuxKernelVariablesSpec{
		KernelVariables: vars,
		NodeName:        s.nodeName,
	}, nil
}

func (s *LinuxKernelVariablesSensor) walkVarsDir(dirPath string, procDir *os.File) ([]KernelVariable, error) {
	var varsNames []string
	varsList := make([]KernelVariable, 0, 128)

	var err error
	for varsNames, err = procDir.Readdirnames(100); err == nil; varsNames, err = procDir.Readdirnames(100) {
		for _, varName := range varsNames {
			hVarFileName := hostPath(path.Join(dirPath, varName))
			varFile, errOpen := os.Open(hVarFileName)
			if errOpen != nil {
				if strings.Contains(errOpen.Error(), "permission denied") {
					logger.L().Debug("failed to open kernel variable file", helpers.String("path", hVarFileName), helpers.Error(errOpen))
					continue
				}
				return nil, fmt.Errorf("failed to open file (%s): %w", hVarFileName, errOpen)
			}
			defer varFile.Close()

			fileInfo, errStat := varFile.Stat()
			if errStat != nil {
				return nil, fmt.Errorf("failed to stat file (%s): %w", hVarFileName, errStat)
			}

			if fileInfo.IsDir() {
				// Recursive call
				innerVars, errW := s.walkVarsDir(path.Join(dirPath, varName), varFile)
				if errW != nil {
					return nil, fmt.Errorf("failed to walkVarsDir file (%s): %w", hVarFileName, errW)
				}
				varsList = append(varsList, innerVars...)
			} else if fileInfo.Mode().IsRegular() {
				strBld := strings.Builder{}
				if _, errCopy := io.Copy(&strBld, varFile); errCopy != nil {
					if strings.Contains(errCopy.Error(), "operation not permitted") {
						logger.L().Debug("failed to read kernel variable file", helpers.String("path", hVarFileName), helpers.Error(errCopy))
						continue
					}
					return nil, fmt.Errorf("failed to copy file (%s): %w", hVarFileName, errCopy)
				}
				varsList = append(varsList, KernelVariable{
					Key:    varName,
					Value:  strBld.String(),
					Source: path.Join(dirPath, varName),
				})
			}
		}
	}

	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read directory (%s): %w", dirPath, err)
	}

	return varsList, nil
}
