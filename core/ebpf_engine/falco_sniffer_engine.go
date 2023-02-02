package ebpf_engine

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"sniffer/core/accumulator_data_structure"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type FalcoSnifferEngine struct {
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

func CreateFalcoSnifferEngine(syscallFilter []string, includeHost bool, sniffMainThreadOnly bool, containerID string) *FalcoSnifferEngine {
	kernelObjPath := os.Getenv("kernelObjPath")
	syscallFilterString := createSyscallFilterString(syscallFilter)

	return &FalcoSnifferEngine{
		kernelObjPath:       kernelObjPath,
		syscallFilterString: syscallFilterString,
		includeHost:         includeHost,
		sniffMainThreadOnly: sniffMainThreadOnly,
		containerID:         containerID,
	}
}

func (FalcoSnifferEngine *FalcoSnifferEngine) snifferEngineCMDWithParams() []string {
	var fullSnifferEngineCMD []string

	if FalcoSnifferEngine.syscallFilterString != "" {
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, "-f")
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, FalcoSnifferEngine.syscallFilterString)
	}
	if FalcoSnifferEngine.includeHost {
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, "-o")
	}
	if FalcoSnifferEngine.sniffMainThreadOnly {
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, "-m")
	}
	if FalcoSnifferEngine.containerID != "" {
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, "-c")
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, FalcoSnifferEngine.containerID)
	}
	fullSnifferEngineCMD = append(fullSnifferEngineCMD, "-e")
	fullSnifferEngineCMD = append(fullSnifferEngineCMD, FalcoSnifferEngine.kernelObjPath)

	return fullSnifferEngineCMD
}

func (FalcoSnifferEngine *FalcoSnifferEngine) StartSnifferEngine() error {
	snifferEngineLoaderPath := os.Getenv("snifferEngineLoaderPath")
	if snifferEngineLoaderPath == "" {
		return fmt.Errorf("startSnifferEngine: the env var snifferEngineLoaderPath is not set")
	}

	fullSnifferEngineCMD := FalcoSnifferEngine.snifferEngineCMDWithParams()
	cmd := exec.Command(snifferEngineLoaderPath, fullSnifferEngineCMD...)
	logger.L().Debug("", helpers.String("cmd.Args %v", fmt.Sprintf("%v", cmd.Args)))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	err = cmd.Start()
	if err != nil {
		logger.L().Debug("", helpers.String("StartSnifferEngine: fail with err %v", fmt.Sprintf("%v", err)))
		return err
	}
	FalcoSnifferEngine.cmd = cmd
	FalcoSnifferEngine.reader = stdout
	FalcoSnifferEngine.pid = cmd.Process.Pid
	return nil
}

func convertStrigTimeToTimeOBJ(Timestamp string) (*time.Time, error) {
	dateAndTime := strings.Split(Timestamp, "T")
	date := strings.Split(dateAndTime[0], "-")
	tm := strings.Split(dateAndTime[1], ":")

	year, err := strconv.Atoi(date[0])
	if err != nil {
		logger.L().Error("", helpers.String("fail strconv %v", fmt.Sprintf("%v", err)))
		return nil, err
	}
	month, err := strconv.Atoi(date[1])
	if err != nil {
		logger.L().Error("", helpers.String("fail strconv %v", fmt.Sprintf("%v", err)))
		return nil, err
	}
	day, err := strconv.Atoi(date[2])
	if err != nil {
		logger.L().Error("", helpers.String("fail strconv %v", fmt.Sprintf("%v", err)))
		return nil, err
	}

	hour, err := strconv.Atoi(tm[0])
	if err != nil {
		logger.L().Error("", helpers.String("fail strconv %v", fmt.Sprintf("%v", err)))
		return nil, err
	}
	minute, err := strconv.Atoi(tm[1])
	if err != nil {
		logger.L().Error("", helpers.String("fail strconv %v", fmt.Sprintf("%v", err)))
		return nil, err
	}
	seconds := strings.Split(tm[2], "+")
	secs := strings.Split(seconds[0], ".")

	sec, err := strconv.Atoi(secs[0])
	if err != nil {
		logger.L().Error("", helpers.String("fail strconv %v", fmt.Sprintf("%v", err)))
		return nil, err
	}

	nsec, err := strconv.Atoi(secs[1])
	if err != nil {
		logger.L().Error("", helpers.String("fail strconv %v", fmt.Sprintf("%v", err)))
		return nil, err
	}

	t := time.Date(year, time.Month(month), day, hour, minute, sec, nsec, time.Now().Location())
	return &t, nil
}

func parseLine(line string) (*accumulator_data_structure.SnifferEventData, error) {
	if strings.Contains(line, "drop event occured") {
		return &accumulator_data_structure.SnifferEventData{
			Cmd: "drop event occured\n",
		}, nil
	}
	lineParts := strings.Split(line, "]::[")
	if len(lineParts) != 8 {
		logger.L().Error("", helpers.String("we have got unknown line format, line is ", fmt.Sprintf("%s", line)))
		return nil, fmt.Errorf("we have got unknown line format, line is %s", line)
	}
	Timestamp, err := convertStrigTimeToTimeOBJ(lineParts[0])
	if err != nil {
		logger.L().Error("", helpers.String("parseLine Timestamp fail line is ", fmt.Sprintf("%s, err %v", line, err)))
		return nil, fmt.Errorf("parseLine Timestamp fail line is %s, err %v", line, err)
	}
	return &accumulator_data_structure.SnifferEventData{
		Timestamp:       *Timestamp,
		ContainerID:     lineParts[1],
		SyscallCategory: lineParts[2],
		Ppid:            lineParts[3],
		Pid:             lineParts[4],
		SyscallType:     lineParts[5],
		Exe:             lineParts[6],
		Cmd:             lineParts[7],
	}, nil
}

func (FalcoSnifferEngine *FalcoSnifferEngine) GetSnifferData(ebpfEngineDataChannel chan *accumulator_data_structure.SnifferEventData) {
	for {
		scanner := bufio.NewScanner(FalcoSnifferEngine.reader)
		for scanner.Scan() {
			fullLine := scanner.Text()
			// logger.L().Info("", helpers.String("line ", fmt.Sprintf("%v", fullLine)))
			if fullLine != "" {
				data, err := parseLine(fullLine)
				if err != nil {
					continue
				}
				ebpfEngineDataChannel <- data
			}
		}
		logger.L().Info("", helpers.String("CacheAccumulator accumulateSnifferData scanner.Err(): ", fmt.Sprintf("%v", scanner.Err())))
	}
}

func (FalcoSnifferEngine *FalcoSnifferEngine) GetEbpfEngineError() error {
	return FalcoSnifferEngine.cmd.Wait()
}
