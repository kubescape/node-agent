package ebpfeng

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"sniffer/internal/config"
	ebpfev "sniffer/pkg/ebpfev/v1"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type FalcoEbpfEngine struct {
	kernelObjPath       string
	syscallFilterString string
	includeHost         bool
	sniffMainThreadOnly bool
	containerID         string
	reader              io.ReadCloser
	pid                 int
	cmd                 *exec.Cmd
}

func createSyscallFilterString(syscallFilter []string) string {
	filterString := ""

	for i := range syscallFilter {
		filterString += "evt.type=" + syscallFilter[i]
		if i < len(syscallFilter)-1 {
			filterString += " or "
		}
	}
	return filterString
}

func CreateFalcoEbpfEngine(syscallFilter []string, includeHost bool, sniffMainThreadOnly bool, containerID string) *FalcoEbpfEngine {
	kernelObjPath := config.GetFalcoKernelObjPath()
	syscallFilterString := createSyscallFilterString(syscallFilter)

	return &FalcoEbpfEngine{
		kernelObjPath:       kernelObjPath,
		syscallFilterString: syscallFilterString,
		includeHost:         includeHost,
		sniffMainThreadOnly: sniffMainThreadOnly,
		containerID:         containerID,
	}
}

func (FalcoEbpfEngine *FalcoEbpfEngine) ebpfEngineCMDWithParams() []string {
	var fullEbpfEngineCMD []string

	if FalcoEbpfEngine.syscallFilterString != "" {
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, "-f")
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, FalcoEbpfEngine.syscallFilterString)
	}
	if FalcoEbpfEngine.includeHost {
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, "-o")
	}
	if FalcoEbpfEngine.sniffMainThreadOnly {
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, "-m")
	}
	if FalcoEbpfEngine.containerID != "" {
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, "-c")
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, FalcoEbpfEngine.containerID)
	}
	fullEbpfEngineCMD = append(fullEbpfEngineCMD, "-e")
	fullEbpfEngineCMD = append(fullEbpfEngineCMD, FalcoEbpfEngine.kernelObjPath)

	return fullEbpfEngineCMD
}

func (FalcoEbpfEngine *FalcoEbpfEngine) StartEbpfEngine() error {
	ebpfEngineLoaderPath := config.GetEbpfEngineLoaderPath()
	if ebpfEngineLoaderPath == "" {
		return fmt.Errorf("StartEbpfEngine: the ebpfEngineLoaderPath is not configured")
	}

	fullEbpfEngineCMD := FalcoEbpfEngine.ebpfEngineCMDWithParams()
	cmd := exec.Command(ebpfEngineLoaderPath, fullEbpfEngineCMD...)
	logger.L().Debug("", helpers.String("cmd.Args %v", fmt.Sprintf("%v", cmd.Args)))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	err = cmd.Start()
	if err != nil {
		logger.L().Debug("", helpers.String("StartEbpfEngine: fail with err %v", fmt.Sprintf("%v", err)))
		return err
	}
	FalcoEbpfEngine.cmd = cmd
	FalcoEbpfEngine.reader = stdout
	FalcoEbpfEngine.pid = cmd.Process.Pid
	return nil
}

func convertStringTimeToTimeOBJ(timestamp string) (*time.Time, error) {
	dateAndTime := strings.Split(timestamp, "T")
	date := strings.Split(dateAndTime[0], "-")
	tm := strings.Split(dateAndTime[1], ":")

	year, err := strconv.Atoi(date[0])
	if err != nil {
		logger.L().Error("fail strconv", helpers.Error(err))
		return nil, err
	}
	month, err := strconv.Atoi(date[1])
	if err != nil {
		logger.L().Error("fail strconv", helpers.Error(err))
		return nil, err
	}
	day, err := strconv.Atoi(date[2])
	if err != nil {
		logger.L().Error("fail strconv", helpers.Error(err))
		return nil, err
	}

	hour, err := strconv.Atoi(tm[0])
	if err != nil {
		logger.L().Error("fail strconv", helpers.Error(err))
		return nil, err
	}
	minute, err := strconv.Atoi(tm[1])
	if err != nil {
		logger.L().Error("fail strconv", helpers.Error(err))
		return nil, err
	}
	seconds := strings.Split(tm[2], "+")
	secs := strings.Split(seconds[0], ".")

	sec, err := strconv.Atoi(secs[0])
	if err != nil {
		logger.L().Error("fail strconv", helpers.Error(err))
		return nil, err
	}

	nsec, err := strconv.Atoi(secs[1])
	if err != nil {
		logger.L().Error("fail strconv", helpers.Error(err))
		return nil, err
	}

	t := time.Date(year, time.Month(month), day, hour, minute, sec, nsec, time.Now().Location())
	return &t, nil
}

func parseLine(line string) (*ebpfev.EventData, error) {
	if strings.Contains(line, "drop event occured") {
		return ebpfev.CreateKernelEvent(nil, "", "", "", "", "", "", "drop event occurred\n"), nil
	}
	lineParts := strings.Split(line, "]::[")
	if len(lineParts) != 8 {
		logger.L().Error("", helpers.String("we have got unknown line format, line is ", fmt.Sprintf("%s", line)))
		return nil, fmt.Errorf("we have got unknown line format, line is %s", line)
	}
	Timestamp, err := convertStringTimeToTimeOBJ(lineParts[0])
	if err != nil {
		logger.L().Error("", helpers.String("parseLine Timestamp fail line is ", fmt.Sprintf("%s, err %v", line, err)))
		return nil, fmt.Errorf("parseLine Timestamp fail line is %s, err %v", line, err)
	}
	return ebpfev.CreateKernelEvent(Timestamp, lineParts[1], lineParts[2], lineParts[3], lineParts[4], lineParts[5], lineParts[6], lineParts[7]), nil
}

func (FalcoEbpfEngine *FalcoEbpfEngine) GetData(ebpfEngineDataChannel chan *ebpfev.EventData) {
	for {
		scanner := bufio.NewScanner(FalcoEbpfEngine.reader)
		for scanner.Scan() {
			fullLine := scanner.Text()
			if fullLine != "" {
				data, err := parseLine(fullLine)
				if err != nil {
					continue
				}
				ebpfEngineDataChannel <- data
			}
		}
		logger.L().Info("", helpers.String("CacheAccumulator accumulateEbpfEngineData scanner.Err(): ", fmt.Sprintf("%v", scanner.Err())))
	}
}

func (FalcoEbpfEngine *FalcoEbpfEngine) GetEbpfEngineError() error {
	return FalcoEbpfEngine.cmd.Wait()
}
