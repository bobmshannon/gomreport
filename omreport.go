package omreport

import (
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

const (
	// DefaultOMCLIProxyDir is the default path to directory that contains omcliproxy.
	DefaultOMCLIProxyDir = "/opt/dell/srvadmin/sbin"

	// DefaultOMCLIProxyBinaryName is the default name of the omcliproxy binary.
	DefaultOMCLIProxyBinaryName = "omcliproxy"

	// DefaultOMReportCommandName is the default name of omreport subcommand passed to omcliproxy.
	DefaultOMReportCommandName = "omreport"
)

// An OMReporter gathers information from Dell's omreport utility.
type OMReporter interface {
	Report(...string) ([]byte, error)
	Chassis() (*ChassisOutput, error)
	ChassisInfo() (*ChassisInfoOutput, error)
	ChassisBatteries() (*ChassisBatteriesOutput, error)
	ChassisFans() (*ChassisFansOutput, error)
	ChassisProcessors() (*ChassisProcessorsOutput, error)
	ChassisMemory() (*ChassisMemoryOutput, error)
	ChassisTemps() (*ChassisTempsOutput, error)
	ChassisPowerMonitoring() (*ChassisPowerMonitoringOutput, error)
	ChassisPowerSupplies() (*ChassisPowerSuppliesOutput, error)
	StorageController() (*StorageControllerOutput, error)
	StorageEnclosure() (*StorageEnclosureOutput, error)
	StorageVDisk() (*StorageVDiskOutput, error)
	StoragePDisk(cid int) (*StoragePDiskOutput, error)
	SuspiciousOMCLIProxyBinary() error
}

// OMReport implements OMReporter.
type OMReport struct {
	omCLIProxyPath       string
	enhancedSecurityMode bool

	sha256Checksum []byte
}

type Config struct {
	// Full path to the omcliproxy binary.
	OMCLIProxyPath string

	// Whether or not to enable enhanced security mode.
	// Enabling this checks the sha256 of the omcliproxy binary
	// and ensures that it has not been modified prior to executing it.
	EnhancedSecurityMode bool
}

// NewOMReporter returns a struct that implements OMReporter.
// Returns an error if the provided path to omcliproxy is potentially
// malicious and doesn't match known signatures.
func NewOMReporter(cfg *Config) (*OMReport, error) {
	om := &OMReport{
		omCLIProxyPath:       cfg.OMCLIProxyPath,
		enhancedSecurityMode: cfg.EnhancedSecurityMode,
	}
	if err := om.allowedOMCLIProxyBinary(); err != nil {
		return nil, err
	}
	checksum, err := fileSha256(cfg.OMCLIProxyPath)
	if err != nil {
		return nil, err
	}
	om.sha256Checksum = checksum
	return om, nil
}

// Report runs the specified omreport command with provided arguments.
func (om *OMReport) Report(args ...string) ([]byte, error) {
	if om.omCLIProxyPath == "" {
		om.omCLIProxyPath = filepath.Join(DefaultOMCLIProxyDir, DefaultOMCLIProxyBinaryName)
	}
	if om.enhancedSecurityMode {
		if err := om.SuspiciousOMCLIProxyBinary(); err != nil {
			return nil, err
		}
	}
	args = append([]string{DefaultOMReportCommandName}, args...)
	args = append(args, "-fmt", "xml")
	return exec.Command(om.omCLIProxyPath, args...).CombinedOutput()
}

// About returns OMSA version information gathered from omreport.
func (om *OMReport) About() (*AboutOutput, error) {
	data, err := om.Report("about")
	if err != nil {
		return nil, err
	}
	out := AboutOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Chassis returns server chassis information gathered from omreport.
func (om *OMReport) Chassis() (*ChassisOutput, error) {
	data, err := om.Report("chassis")
	if err != nil {
		return nil, err
	}
	out := ChassisOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChassisBatteries returns battery information gathered from omreport.
func (om *OMReport) ChassisBatteries() (*ChassisBatteriesOutput, error) {
	data, err := om.Report("chassis", "batteries")
	if err != nil {
		return nil, err
	}
	out := ChassisBatteriesOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChassisFans returns fan information gathered from omreport.
func (om *OMReport) ChassisFans() (*ChassisFansOutput, error) {
	data, err := om.Report("chassis", "fans")
	if err != nil {
		return nil, err
	}
	out := ChassisFansOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChassisInfo returns chassis information gathered from omreport.
func (om *OMReport) ChassisInfo() (*ChassisInfoOutput, error) {
	data, err := om.Report("chassis", "info")
	if err != nil {
		return nil, err
	}
	out := ChassisInfoOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, err
}

// ChassisProcessors returns processor information gathered from omreport.
func (om *OMReport) ChassisProcessors() (*ChassisProcessorsOutput, error) {
	data, err := om.Report("chassis", "processors")
	if err != nil {
		return nil, err
	}
	out := ChassisProcessorsOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChassisMemory returns memory information gathered from omreport.
func (om *OMReport) ChassisMemory() (*ChassisMemoryOutput, error) {
	data, err := om.Report("chassis", "memory")
	if err != nil {
		return nil, err
	}
	out := ChassisMemoryOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChassisTemps returns temperature information gathered from omreport.
func (om *OMReport) ChassisTemps() (*ChassisTempsOutput, error) {
	data, err := om.Report("chassis", "temps")
	if err != nil {
		return nil, err
	}
	out := ChassisTempsOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChassisPowerMonitoring returns power monitoring information gathered from omreport.
func (om *OMReport) ChassisPowerMonitoring() (*ChassisPowerMonitoringOutput, error) {
	data, err := om.Report("chassis", "pwrmonitoring")
	if err != nil {
		return nil, err
	}
	out := ChassisPowerMonitoringOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChassisPowerSupplies returns power supply information gathered from omreport.
func (om *OMReport) ChassisPowerSupplies() (*ChassisPowerSuppliesOutput, error) {
	data, err := om.Report("chassis", "pwrsupplies")
	if err != nil {
		return nil, err
	}
	out := ChassisPowerSuppliesOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StorageController returns RAID controller information gathered from omreport.
func (om *OMReport) StorageController() (*StorageControllerOutput, error) {
	data, err := om.Report("storage", "controller")
	if err != nil {
		return nil, err
	}
	out := StorageControllerOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StorageEnclosure returns storage enclosure information gathered from omreport.
func (om *OMReport) StorageEnclosure() (*StorageEnclosureOutput, error) {
	data, err := om.Report("storage", "enclosure")
	if err != nil {
		return nil, err
	}
	out := StorageEnclosureOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StorageVDisk returns virtual disk information gathered from omreport.
func (om *OMReport) StorageVDisk() (*StorageVDiskOutput, error) {
	data, err := om.Report("storage", "vdisk")
	if err != nil {
		return nil, err
	}
	out := StorageVDiskOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StoragePDisk returns physical disk information associated with the provided storage
// controller gathered from omreport.
func (om *OMReport) StoragePDisk(cid int) (*StoragePDiskOutput, error) {
	data, err := om.Report("storage", "pdisk", fmt.Sprintf("controller=%d", cid))
	if err != nil {
		return nil, err
	}
	out := StoragePDiskOutput{}
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FailurePredicted returns true if a physical disk is in a failure predicted state.
// Returns an error if attribute cannot be determined.
func (p *PDisk) FailurePredicted() (bool, error) {
	attr, err := strconv.ParseInt(p.AttributesMask, 2, 64)
	return (attr & AttrFailurePredicted) > 0, err
}

// GlobalHotSpare returns true if a physical disk is a global hot spare.
// Returns an error if attribute cannot be determined.
func (p *PDisk) GlobalHotSpare() (bool, error) {
	attr, err := strconv.ParseInt(p.AttributesMask, 2, 64)
	return (attr & AttrGlobalHS) > 0, err
}

// DedicatedHotSpare returns true if a physical disk is a dedicated hot spare.
// Returns an error if attribute cannot be determined.
func (p *PDisk) DedicatedHotSpare() (bool, error) {
	attr, err := strconv.ParseInt(p.AttributesMask, 2, 64)
	return (attr & AttrDedicatedHS) > 0, err
}

// allowedOMCLIProxyBinary checks if the configured path to the omcliproxy executable is allowed to be executed.
// An omcliproxy executable is allowed to be executed if all of the following conditions are true:
//  - The binary name is 'omcliproxy'.
//  - The path is not a symlink.
// Returns an error if the binary is not allowed to be executed or does not exist.
func (om *OMReport) allowedOMCLIProxyBinary() error {
	// The binary name must be 'omcliproxy'.
	name := filepath.Base(om.omCLIProxyPath)
	if name != DefaultOMCLIProxyBinaryName {
		return fmt.Errorf("expected binary name to be %s", DefaultOMCLIProxyBinaryName)
	}

	// The path must not be a symlink.
	fi, err := os.Lstat(om.omCLIProxyPath)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("expected %s to not be a symlink", om.omCLIProxyPath)
	}

	return nil
}

// SuspiciousOMCLIProxyBinary is a method that can be called by clients to check whether the configured
// omcliproxy binary is suspicious. The binary is considered suspicious if its sha256 checksum is different
// from the checksum computed when the omreport object was first instantiated using NewOMReporter. This implies
// that something has changed the the executable contents underneath this process and that further execution should
// proceed with caution.
// Returns a non-nil error if the binary is considered suspicious or if the file checksum cannot be calculated.
func (om *OMReport) SuspiciousOMCLIProxyBinary() error {
	currentChecksum, err := fileSha256(om.omCLIProxyPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(currentChecksum, om.sha256Checksum) {
		return fmt.Errorf("current binary checksum %s does not match the original checksum %s which is very suspicious", currentChecksum, om.sha256Checksum)
	}
	return nil
}

// fileSha256 returns the sha256 checksum of the specified file.
func fileSha256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	if err := f.Close(); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
