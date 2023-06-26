package ebpfeng

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"sniffer/pkg/config"
	"sniffer/pkg/context"
	"sniffer/pkg/ebpfev"
	ebpfev1 "sniffer/pkg/ebpfev/v1"

	"github.com/kubescape/go-logger"
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

var _ EbpfEngineClient = (*FalcoEbpfEngine)(nil)

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
	kernelObjPath := config.GetConfigurationConfigContext().GetFalcoKernelObjPath()
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
	ebpfEngineLoaderPath := config.GetConfigurationConfigContext().GetEbpfEngineLoaderPath()
	if ebpfEngineLoaderPath == "" {
		return fmt.Errorf("StartEbpfEngine: the ebpfEngineLoaderPath is not configured")
	}

	fullEbpfEngineCMD := FalcoEbpfEngine.ebpfEngineCMDWithParams()
	cmd := exec.Command(ebpfEngineLoaderPath, fullEbpfEngineCMD...)
	logger.L().Debug("start ebpf engine process", helpers.String("cmd.Args", fmt.Sprintf("%v", cmd.Args)))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	err = cmd.Start()
	if err != nil {
		logger.L().Error("failed to start ebpf engine process", helpers.Error(err))
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
		return nil, err
	}
	month, err := strconv.Atoi(date[1])
	if err != nil {
		return nil, err
	}
	day, err := strconv.Atoi(date[2])
	if err != nil {
		return nil, err
	}

	hour, err := strconv.Atoi(tm[0])
	if err != nil {
		return nil, err
	}
	minute, err := strconv.Atoi(tm[1])
	if err != nil {
		return nil, err
	}
	seconds := strings.Split(tm[2], "+")
	secs := strings.Split(seconds[0], ".")

	sec, err := strconv.Atoi(secs[0])
	if err != nil {
		return nil, err
	}

	nsec, err := strconv.Atoi(secs[1])
	if err != nil {
		return nil, err
	}

	t := time.Date(year, time.Month(month), day, hour, minute, sec, nsec, time.Now().Location())
	return &t, nil
}

func parseLine(line string) (ebpfev.EventClient, error) {
	if strings.Contains(line, "drop event occured") {
		now := time.Now()
		return ebpfev1.CreateKernelEvent(&now, "", "", "", "", "", "", "drop event occurred\n"), nil
	}
	lineParts := strings.Split(line, "]::[")
	if len(lineParts) != 8 {
		logger.L().Ctx(context.GetBackgroundContext()).Error("failed to parse data from ebpf engine", helpers.String("we have got unknown line format, line is", line))
		return nil, fmt.Errorf("we have got unknown line format, line is %s", line)
	}
	timestamp, err := convertStringTimeToTimeOBJ(lineParts[0])
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Warning("fail to parse timestamp from ebpf engine", []helpers.IDetails{helpers.String("timestamp", lineParts[0]), helpers.Error(err)}...)
		return nil, fmt.Errorf("parseLine Timestamp fail line is %s, err %v", line, err)
	}
	return ebpfev1.CreateKernelEvent(timestamp, lineParts[1], lineParts[2], lineParts[3], lineParts[4], lineParts[5], lineParts[6], lineParts[7]), nil
}

func (FalcoEbpfEngine *FalcoEbpfEngine) GetData(ebpfEngineDataChannel chan ebpfev.EventClient) {
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
		logger.L().Ctx(context.GetBackgroundContext()).Error("failed to get data from ebpf engine process", helpers.Error(scanner.Err()))
		break
	}
}

func (FalcoEbpfEngine *FalcoEbpfEngine) GetEbpfEngineError() error {
	return FalcoEbpfEngine.cmd.Wait()
}
