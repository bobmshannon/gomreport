package omreport

import (
	"fmt"
)

// BusProtocol models the bus protocol used by a hardware component.
type BusProtocol int

// Status models the status of a hardware component (e.g. OK, Critical, NonCritical).
type Status int

// State models the state of a hardware component (e.g. Ready, Degraded, Failed, etc.)
type State int

// Layout models the layout of a RAID (e.g. RAID-0, RAID-1, RAID-10, etc.)
type Layout int

const (
	AttrLogicalConnector = 1 << 6
	AttrGlobalHS         = 1 << 7
	AttrDedicatedHS      = 1 << 8
	AttrNonRAID          = 1 << 9
	AttrFailurePredicted = 1 << 11

	StatusOK          Status = 2
	StatusNonCritical Status = 3
	StatusCritical    Status = 4

	StateReady                    State = 1
	StateFailed                   State = 2
	StateOnline                   State = 4
	StateOffline                  State = 8
	StateDegraded                 State = 32
	StateNonRAID                  State = 4096
	StateReplacing                State = 2097152
	StateRebuilding               State = 8388608
	StateBackgroundInitialization State = 34359738368
	StateForeign                  State = 274877906944
	StateClear                    State = 549755813888
	StateDegradedRedundancy       State = 9007199254740992

	LayoutRAID0  Layout = 2
	LayoutRAID1  Layout = 4
	LayoutRAID5  Layout = 64
	LayoutRAID6  Layout = 128
	LayoutRAID60 Layout = 262144

	BusProtocolSCSI BusProtocol = 1
	BusProtocolIDE  BusProtocol = 2
	BusProtocolSATA BusProtocol = 7
	BusProtocolSAS  BusProtocol = 8
	BusProtocolPCIe BusProtocol = 9

	// NaN is an enum for fields that use the string 'N/A'.
	NaN = -1 << 31
)

// AboutOutput models the output of 'omreport about'.
type AboutOutput struct {
	Version string `xml:"About>ProductVersion"`
}

// ChassisOutput models the output of 'omreport chassis'.
type ChassisOutput struct {
	FansStatus            Status `xml:"Parent>fans>computedobjstatus"`
	MemoryStatus          Status `xml:"Parent>memory>computedobjstatus"`
	PowerSuppliesStatus   Status `xml:"Parent>powersupply>computedobjstatus"`
	PowerManagementStatus Status `xml:"Parent>powermonitoring>computedobjstatus"`
	ProcessorsStatus      Status `xml:"Parent>processor>computedobjstatus"`
	TemperaturesStatus    Status `xml:"Parent>temperatures>computedobjstatus"`
	VoltagesStatus        Status `xml:"Parent>voltages>computedobjstatus"`
	HardwareLogStatus     Status `xml:"Parent>esmlog>computedobjstatus"`
	BatteriesStatus       Status `xml:"Parent>batteries>computedobjstatus"`
}

// ChassisBatteriesOutput models the output of 'omreport chassis batteries'.
type ChassisBatteriesOutput struct {
	Probes []BatteryProbe `xml:"BatteryObj"`
}

// ChassisFansOutput models the output of 'omreport chassis fans'.
type ChassisFansOutput struct {
	Probes []FanProbe `xml:"Chassis>FanProbeList>FanProbe"`
}

// ChassisProcessorsOutput models the output of 'omreport chassis processors'.
type ChassisProcessorsOutput struct {
	Processors []Processor      `xml:"ProcessorList>ProcessorConn"`
	Probes     []ProcessorProbe `xml:"CPUStatusProbeList>CPUStatusProbe"`
}

// ChassisPowerMonitoringOutput models the output of 'omreport chassis pwrmonitoring'.
type ChassisPowerMonitoringOutput struct {
	Probes []PowerProbe `xml:"CurrentProbeList>CurrentProbe"`
	Status Status       `xml:"ObjStatus"`
}

// ChassisMemoryOutput models the output of 'omreport chassis memory'.
type ChassisMemoryOutput struct {
	TotalPhysicalMemorySize     float64 `xml:"MemoryInfo>TotalPhysMemorySize"`
	AvailablePhysicalMemorySize float64 `xml:"MemoryInfo>AvailPhysMemorySize"`
	Dimms                       []Dimm  `xml:"MemDevObj"`
	Status                      Status  `xml:"ObjStatus"`
}

// ChassisPowerSuppliesOutput models the output of 'omreport chassis pwrsupplies'.
type ChassisPowerSuppliesOutput struct {
	PowerSupplies []PowerSupply `xml:"Chassis>PowerSupplyList>PowerSupply"`
}

// ChassisTempsOutput models the output of 'omreport chassis temps'.
type ChassisTempsOutput struct {
	Probes []TemperatureProbe `xml:"Chassis>TemperatureProbeList>TemperatureProbe"`
}

// StorageVDiskOutput models the output of 'omreport storage vdisk'.
type StorageVDiskOutput struct {
	VDisks []VDisk `xml:"VirtualDisks>DCStorageObject"`
}

// StoragePDiskOutput models the output of 'omreport storage pdisk controller=<ID>'.
type StoragePDiskOutput struct {
	PDisks []PDisk `xml:"ArrayDisks>DCStorageObject"`
}

// StorageControllerOutput models the output of 'omreport storage controller'.
type StorageControllerOutput struct {
	Controllers []Controller `xml:"Controllers>DCStorageObject"`
}

// StorageEnclosureOutput models the output of 'omreport storage enclosure'.
type StorageEnclosureOutput struct {
	Enclosures []Enclosure `xml:"Enclosures>DCStorageObject"`
}

// BatteryProbe models a battery probe described by omreport.
type BatteryProbe struct {
	ID       int    `xml:"index,attr"`
	Location string `xml:"ProbeLocation"`
	Status   Status `xml:"probeStatus"`
}

// FanProbe models a fan probe described by omreport.
type FanProbe struct {
	ID                      int     `xml:"index,attr"`
	Reading                 float64 `xml:"ProbeReading"`
	Status                  Status  `xml:"ProbeStatus"`
	Location                string  `xml:"ProbeLocation"`
	MinCriticalThreshold    float64 `xml:"ProbeThresholds>LCThreshold"`
	MinNonCriticalThreshold float64 `xml:"ProbeThresholds>LNCThreshold"`
}

// Processor models a CPU described by omreport.
type Processor struct {
	ID            int     `xml:"index,attr"`
	Name          string  `xml:"DevProcessor>ExtName"`
	MaxSpeed      float64 `xml:"DevProcessor>MaxSpeed"`
	CurrentSpeed  float64 `xml:"DevProcessor>CurSpeed"`
	Manufacturer  string  `xml:"DevProcessor>Manufacturer"`
	Model         string  `xml:"DevProcessor>Brand"`
	PhysicalCores int     `xml:"DevProcessor>CoreCount"`
	VirtualCores  int     `xml:"DevProcessor>ThreadCount"`
	Status        Status  `xml:"status,attr"`
}

// ProcessorProbe models a CPU probe described by omreport.
type ProcessorProbe struct {
	ID                   int    `xml:"index,attr"`
	Location             string `xml:"ProbeLocation"`
	InternalError        bool   `xml:"ProcessorStatus>CPUStatusIErr"`
	ThermTrip            bool   `xml:"ProcessorStatus>CPUStatusThermTrip"`
	ConfigError          bool   `xml:"ProcessorStatus>CPUStatusConfigErr"`
	PresenceDetected     bool   `xml:"ProcessorStatus>CPUStatusPresenceDetected"`
	Disabled             bool   `xml:"ProcessorStatus>CPUStatusDisabled"`
	TermPresenceDetected bool   `xml:"ProcessorStatus>CPUStatusTermPresenceDetected"`
	Throttled            bool   `xml:"ProcessorStatus>CPUStatusThrottled"`
}

// TemperatureProbe models a temperature probe described by omreport.
type TemperatureProbe struct {
	ID       int     `xml:"index,attr"`
	Reading  float64 `xml:"ProbeReading"`
	Status   Status  `xml:"ProbeStatus"`
	Location string  `xml:"ProbeLocation"`
}

// Controller models a controller described by omreport.
type Controller struct {
	ID     int    `xml:"ControllerNum"`
	Name   string `xml:"Name"`
	Status Status `xml:"ObjStatus"`
	State  State  `xml:"ObjState"`
}

// Enclosure models a enclosure described by omreport.
type Enclosure struct {
	ID           int    `xml:"EnclosureID"`
	ControllerID int    `xml:"ControllerNum"`
	Status       Status `xml:"ObjStatus"`
	State        State  `xml:"ObjState"`
}

// VDisk models a virtual disk described by omreport.
type VDisk struct {
	ID          int         `xml:"DeviceID"`
	BusProtocol BusProtocol `xml:"BusProtocol"`
	Name        string      `xml:"Name"`
	DeviceName  string      `xml:"DeviceName"`
	Layout      Layout      `xml:"Layout"`
	State       State       `xml:"ObjState"`
	Status      Status      `xml:"ObjStatus"`
	Size        int         `xml:"Length"`
}

// PDisk models a physical disk described by omreport.
type PDisk struct {
	AttributesMask string      `xml:"AttributesMask"`
	BusProtocol    BusProtocol `xml:"BusProtocol"`
	ID             int         `xml:"DeviceID"`
	ControllerID   int         `xml:"ControllerNum"`
	EnclosureID    int         `xml:"EnclosureID"`
	PartNo         string      `xml:"PartNo"`
	ProductID      string      `xml:"ProductID"`
	SerialNo       string      `xml:"DeviceSerialNumber"`
	SlotNo         int         `xml:"EnclosureIndex"`
	Status         Status      `xml:"ObjStatus"`
	State          State       `xml:"ObjState"`
	Vendor         string      `xml:"Vendor"`
}

// PowerSupply models a power supply described by omreport.
type PowerSupply struct {
	ID                     int              `xml:"index,attr"`
	InputRatedWatts        float64          `xml:"InputRatedWatts"`
	FirmwareVersion        string           `xml:"FirmWareVersion"`
	PowerMonitoringCapable bool             `xml:"PMCapable"`
	OutputWatts            float64          `xml:"OutputWatts"`
	Location               string           `xml:"PSLocation"`
	State                  PowerSupplyState `xml:"PSState"`
}

// PowerSupplyState models the state of a power supply.
type PowerSupplyState struct {
	PresenceDetected      bool `xml:"PSPresenceDetected"`
	FailureDetected       bool `xml:"PSFailureDetected"`
	PredictiveFailure     bool `xml:"PSPredictiveFailure"`
	ACLost                bool `xml:"PSACLost"`
	ACLostOrOutOfRange    bool `xml:"PSACLostorOutofRange"`
	ACPresentOrOutOfRange bool `xml:"PSACPresentorOutofRange"`
	ConfigError           bool `xml:"PSConfigError"`
}

// Fans models a group of fans and their status.
type Fans struct {
	Probes []Probe `xml:"FanObj"`
	Status Status  `xml:"computedobjstatus"`
}

// Voltages models a group of voltage probes and their status.
type Voltages struct {
	Probes []Probe `xml:"VoltageObj"`
	Status Status  `xml:"computedobjstatus"`
}

// Dimm models a single memory module.
type Dimm struct {
	ArrayNo         int    `xml:"deviceSet"`
	AssetTag        string `xml:"AssetTag"`
	Errors          int    `xml:"errCount"`
	MultiBitErrors  int    `xml:"mbErrCount"`
	Name            string `xml:"DeviceLocator"`
	PartNo          string `xml:"PartNumber"`
	SingleBitErrors int    `xml:"sbErrCount"`
}

// Probe models a generic probe.
type Probe struct {
	ID                      int     `xml:"instance,attr"`
	Name                    string  `xml:"ProbeLocation"`
	MinCriticalThreshold    float64 `xml:"probeThresholds>lcThreshold"`
	MinNonCriticalThreshold float64 `xml:"probeThresholds>lncThreshold"`
	MaxCriticalThreshold    float64 `xml:"probeThresholds>ucThreshold"`
	MaxNonCriticalThreshold float64 `xml:"probeThresholds>uncThreshold"`
	Reading                 float64 `xml:"probeReading"`
	Status                  Status  `xml:"objstatus"`
}

// PowerProbe models a power consumption probe.
type PowerProbe struct {
	ID                int     `xml:"index,attr"`
	Name              string  `xml:"ProbeLocation"`
	Reading           float64 `xml:"ProbeReading"`
	Status            Status  `xml:"ProbeStatus"`
	CriticalThreshold float64 `xml:"ProbeThresholds>UCThreshold"`
	WarningThreshold  float64 `xml:"ProbeThresholds>UNCThreshold"`
}

func (s *Status) String() string {
	switch *s {
	case StatusCritical:
		return "Critical"
	case StatusOK:
		return "OK"
	case StatusNonCritical:
		return "Non-critical"
	default:
		return fmt.Sprintf("Unknown status code %s", string(*s))
	}
}

func (s *State) String() string {
	switch *s {
	case StateOnline:
		return "Online"
	case StateBackgroundInitialization:
		return "Background Initialization"
	case StateClear:
		return "Clear"
	case StateDegraded:
		return "Degraded"
	case StateDegradedRedundancy:
		return "Degraded Redundancy"
	case StateFailed:
		return "Failed"
	case StateForeign:
		return "Foreign"
	case StateNonRAID:
		return "Non-RAID"
	case StateOffline:
		return "Offline"
	case StateReady:
		return "Ready"
	case StateRebuilding:
		return "Rebuilding"
	case StateReplacing:
		return "Replacing"
	default:
		return fmt.Sprintf("Unknown state code %s", string(*s))
	}
}

func (b *BusProtocol) String() string {
	switch *b {
	case BusProtocolIDE:
		return "IDE"
	case BusProtocolPCIe:
		return "PCIe"
	case BusProtocolSAS:
		return "SAS"
	case BusProtocolSATA:
		return "SATA"
	case BusProtocolSCSI:
		return "SCSI"
	default:
		return fmt.Sprintf("Unknown bus protocol code %s", string(*b))
	}
}

func (l *Layout) String() string {
	switch *l {
	case LayoutRAID0:
		return "RAID-0"
	case LayoutRAID1:
		return "RAID-1"
	case LayoutRAID5:
		return "RAID-5"
	case LayoutRAID6:
		return "RAID-6"
	case LayoutRAID60:
		return "RAID-60"
	default:
		return fmt.Sprintf("Unknown layout code %s", string(*l))
	}
}
