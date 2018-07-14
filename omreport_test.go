package omreport

import (
	"encoding/xml"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOMReporter(t *testing.T) {
	t.Run("not allowed omcliproxy binary name", func(t *testing.T) {
		_, err := NewOMReporter(&Config{
			OMCLIProxyPath:       "testdata/maliciousproxy",
			EnhancedSecurityMode: true,
		})
		require.Error(t, err, "testdata/maliciousproxy should not be allowed")
	})
	t.Run("not allowed omcliproxy binary that is a symlink", func(t *testing.T) {
		_, err := NewOMReporter(&Config{
			OMCLIProxyPath:       "testdata/maliciousproxylink",
			EnhancedSecurityMode: true,
		})
		require.Error(t, err, "testdata/maliciousproxylink should not be allowed")
	})
	t.Run("allowed omcliproxy binary", func(t *testing.T) {
		_, err := NewOMReporter(&Config{
			OMCLIProxyPath:       "testdata/omcliproxy",
			EnhancedSecurityMode: true,
		})
		require.NoError(t, err, "testdata/omcliproxy should be allowed")
	})
}

func TestOMReport_SuspiciousOMCLIProxyBinary(t *testing.T) {
	t.Run("non-suspicious omcliproxy binary", func(t *testing.T) {
		om, err := NewOMReporter(&Config{
			OMCLIProxyPath:       "testdata/omcliproxy",
			EnhancedSecurityMode: true,
		})
		require.NoError(t, err)
		err = om.SuspiciousOMCLIProxyBinary()
		require.NoError(t, err, "testdata/omcliproxy should not be considered suspicious")

	})
	t.Run("suspicious omcliproxy binary", func(t *testing.T) {
		tmpDir, err := ioutil.TempDir(".", "")
		require.NoError(t, err)
		defer func() {
			err := os.RemoveAll(tmpDir)
			require.NoError(t, err)
		}()
		binaryPath := filepath.Join(tmpDir, "omcliproxy")
		require.NoError(t, err)
		err = ioutil.WriteFile(binaryPath, []byte("foo"), 0644)
		require.NoError(t, err)

		om, err := NewOMReporter(&Config{
			OMCLIProxyPath:       binaryPath,
			EnhancedSecurityMode: true,
		})
		require.NoError(t, err)

		err = ioutil.WriteFile(binaryPath, []byte("bar"), 0644)
		require.NoError(t, err)

		err = om.SuspiciousOMCLIProxyBinary()
		require.Error(t, err, "modified omcliproxy binary should be considered suspicious")

		err = ioutil.WriteFile(binaryPath, []byte("foo"), 0644)
		require.NoError(t, err)
		err = om.SuspiciousOMCLIProxyBinary()
		require.NoError(t, err, "omcliproxy binary should no longer be considered suspicious after reverting modifications to known checksum")
	})
}

func TestOMReport_fileSha256(t *testing.T) {
	expectedChecksum := []byte("\x9c\xe4\xd2\x05\xed\xe1ұ\xcf\xc0\xa2\xe7\xfb\xb4\xf1\xad\xcf\xd0\xd8\xd07\fw\xba\xe3\f#\xa1*x@T")
	calculatedChecksum, err := fileSha256("testdata/omcliproxy")
	require.NoError(t, err)
	assert.Equal(t, expectedChecksum, calculatedChecksum)
}

func TestOMReport_About_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-about.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := AboutOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)
	assert.Equal(t, AboutOutput{
		Version: "8.5.0",
	}, out)
}

func TestOMReport_Chassis_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-chassis.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := ChassisOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)
	assert.Equal(t, ChassisOutput{
		FansStatus:            StatusOK,
		PowerSuppliesStatus:   StatusCritical,
		PowerManagementStatus: StatusOK,
		ProcessorsStatus:      StatusOK,
		MemoryStatus:          StatusOK,
		TemperaturesStatus:    StatusOK,
		VoltagesStatus:        StatusOK,
		HardwareLogStatus:     StatusOK,
		BatteriesStatus:       StatusOK,
	}, out)
}

func TestOMReport_ChassisTemps_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-chassis-temps.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := ChassisTempsOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)
	assert.Equal(t, ChassisTempsOutput{
		Probes: []TemperatureProbe{
			{
				ID:       0,
				Reading:  180,
				Status:   StatusOK,
				Location: "System Board Inlet Temp",
			},
		},
	}, out)
}

func TestOMReport_StorageVDisk_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-storage-vdisk.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := StorageVDiskOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)
	assert.Equal(t, StorageVDiskOutput{
		VDisks: []VDisk{
			{
				ID:          0,
				BusProtocol: BusProtocolSATA,
				Name:        "OS",
				DeviceName:  "/dev/sda",
				Layout:      LayoutRAID1,
				Status:      StatusOK,
				State:       StateReady,
				Size:        1919716163584,
			},
			{
				ID:          1,
				Name:        "CASS",
				DeviceName:  "/dev/sdb",
				BusProtocol: BusProtocolSATA,
				Layout:      LayoutRAID0,
				Status:      StatusOK,
				State:       StateReady,
				Size:        1919716163584,
			},
		},
	}, out)
}

func TestOMReport_StoragePDisk_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-storage-pdisk.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := StoragePDiskOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)
	assert.Equal(t, StoragePDiskOutput{
		PDisks: []PDisk{
			{
				AttributesMask: "00000000000000000010010000010000",
				ID:             8,
				BusProtocol:    BusProtocolSATA,
				ControllerID:   0,
				EnclosureID:    3,
				PartNo:         "CN09W12RSSX0075V00PFA0",
				ProductID:      "MZ7LM1T9HMJP0D3",
				SerialNo:       "S37PNX0J502096",
				SlotNo:         8,
				Status:         StatusOK,
				State:          StateOnline,
				Vendor:         "DELL(tm)",
			},
			{
				AttributesMask: "00000000000000000010010000010000",
				ID:             9,
				BusProtocol:    BusProtocolSATA,
				ControllerID:   0,
				EnclosureID:    3,
				PartNo:         "CN09W12RSSX0075V00RKA0",
				ProductID:      "MZ7LM1T9HMJP0D3",
				SerialNo:       "S37PNX0J502133",
				SlotNo:         9,
				Status:         StatusOK,
				State:          StateOnline,
				Vendor:         "DELL(tm)",
			},
			{
				AttributesMask: "00000000000000000010010000010000",
				ID:             15,
				BusProtocol:    BusProtocolSATA,
				ControllerID:   0,
				EnclosureID:    3,
				PartNo:         "CN09W12RSSX0075V00R8A0",
				ProductID:      "MZ7LM1T9HMJP0D3",
				SerialNo:       "S37PNX0J502122",
				SlotNo:         15,
				Status:         StatusOK,
				State:          StateOnline,
				Vendor:         "DELL(tm)",
			},
		},
	}, out)
}

func TestOMReport_StorageController_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-storage-controller.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := StorageControllerOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)

	assert.Equal(t, StorageControllerOutput{
		Controllers: []Controller{
			{
				ID:     1,
				Name:   "PERC H710P Mini",
				Status: StatusOK,
				State:  StateReady,
			},
			{
				ID:     0,
				Name:   "PERC H810 Adapter",
				Status: StatusOK,
				State:  StateReady,
			},
		},
	}, out)
}

func TestOMReport_StorageEnclosure_Umarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-storage-enclosure.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := StorageEnclosureOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)

	assert.Equal(t, StorageEnclosureOutput{
		Enclosures: []Enclosure{
			{
				ID:           3,
				ControllerID: 0,
				Status:       StatusOK,
				State:        StateReady,
			},
		},
	}, out)
}

func TestOMReport_ChassisPowerMonitoring_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-chassis-pwrmonitoring.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := ChassisPowerMonitoringOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)

	assert.Equal(t, ChassisPowerMonitoringOutput{
		Probes: []PowerProbe{
			{
				ID:                0,
				Name:              "System Board Pwr Consumption",
				Reading:           114,
				WarningThreshold:  402,
				CriticalThreshold: 483,
				Status:            StatusOK,
			},
			{
				ID:                1,
				Name:              "System Board Current",
				Reading:           5,
				WarningThreshold:  NaN,
				CriticalThreshold: NaN,
				Status:            StatusOK,
			},
		},
		Status: StatusOK,
	}, out)
}

func TestOMReport_ChassisMemory_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-chassis-memory.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := ChassisMemoryOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)

	assert.Equal(t, ChassisMemoryOutput{
		TotalPhysicalMemorySize:     263858184,
		AvailablePhysicalMemorySize: 35390420,
		Dimms: []Dimm{
			{
				ArrayNo:         1,
				AssetTag:        "00172130",
				Errors:          0,
				MultiBitErrors:  0,
				Name:            "A1",
				PartNo:          "HMA84GR7MFR4N-UH",
				SingleBitErrors: 0,
			},
			{
				ArrayNo:         1,
				AssetTag:        "00172130",
				Errors:          0,
				MultiBitErrors:  0,
				Name:            "A2",
				PartNo:          "HMA84GR7MFR4N-UH",
				SingleBitErrors: 0,
			},
		},
		Status: StatusOK,
	}, out)
}

func TestOMReport_ChassisBatteries_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-chassis-batteries.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := ChassisBatteriesOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)

	assert.Equal(t, ChassisBatteriesOutput{
		Probes: []BatteryProbe{
			{
				ID:       0,
				Location: "System Board CMOS Battery",
				Status:   StatusOK,
			},
		},
	}, out)
}

func TestOMReport_ChassisFans_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-chassis-fans.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := ChassisFansOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)

	assert.Equal(t, ChassisFansOutput{
		Probes: []FanProbe{
			{
				ID:                      0,
				Location:                "Chassis Fan1A",
				Status:                  StatusOK,
				Reading:                 5880,
				MinCriticalThreshold:    2880,
				MinNonCriticalThreshold: 3360,
			},
			{
				ID:                      1,
				Location:                "Chassis Fan2",
				Status:                  StatusOK,
				Reading:                 7560,
				MinCriticalThreshold:    3720,
				MinNonCriticalThreshold: 4440,
			},
		},
	}, out)
}

func TestOMReport_ChassisProcessors_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-chassis-processors.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := ChassisProcessorsOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)

	assert.Equal(t, ChassisProcessorsOutput{
		Processors: []Processor{
			{
				ID:            0,
				Name:          "CPU1",
				MaxSpeed:      4000,
				CurrentSpeed:  2400,
				Manufacturer:  "Intel",
				Model:         "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
				Status:        StatusOK,
				PhysicalCores: 14,
				VirtualCores:  28,
			},
			{
				ID:            1,
				Name:          "CPU2",
				MaxSpeed:      4000,
				CurrentSpeed:  2400,
				Manufacturer:  "Intel",
				Model:         "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
				Status:        StatusOK,
				PhysicalCores: 14,
				VirtualCores:  28,
			},
		},
		Probes: []ProcessorProbe{
			{
				ID:                   0,
				Location:             "CPU1",
				InternalError:        false,
				ThermTrip:            false,
				ConfigError:          false,
				PresenceDetected:     true,
				Disabled:             false,
				TermPresenceDetected: false,
				Throttled:            false,
			},
			{
				ID:                   1,
				Location:             "CPU2",
				InternalError:        false,
				ThermTrip:            false,
				ConfigError:          false,
				PresenceDetected:     true,
				Disabled:             false,
				TermPresenceDetected: false,
				Throttled:            false,
			},
		},
	}, out)
}

func TestOMReport_ChassisPowerSupplies_Unmarshal(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/omreport-chassis-pwrsupplies.xml")
	require.NoError(t, err, "Failed to read testdata.")

	out := ChassisPowerSuppliesOutput{}
	err = xml.Unmarshal(data, &out)
	require.NoError(t, err)

	assert.Equal(t, ChassisPowerSuppliesOutput{
		PowerSupplies: []PowerSupply{
			{
				ID:                     0,
				InputRatedWatts:        12600,
				OutputWatts:            11000,
				FirmwareVersion:        "07.12.52",
				Location:               "PS1 Status",
				PowerMonitoringCapable: true,
				State: PowerSupplyState{
					PresenceDetected:      true,
					FailureDetected:       false,
					PredictiveFailure:     false,
					ACLost:                false,
					ACLostOrOutOfRange:    false,
					ACPresentOrOutOfRange: false,
					ConfigError:           false,
				},
			},
			{
				ID:                     1,
				InputRatedWatts:        12320,
				OutputWatts:            11000,
				FirmwareVersion:        "07.12.52",
				Location:               "PS2 Status",
				PowerMonitoringCapable: true,
				State: PowerSupplyState{
					PresenceDetected:      true,
					FailureDetected:       false,
					PredictiveFailure:     false,
					ACLost:                true,
					ACLostOrOutOfRange:    false,
					ACPresentOrOutOfRange: false,
					ConfigError:           false,
				},
			},
		},
	}, out)
}
