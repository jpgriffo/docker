package drivers

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/docker/docker/api"
	"github.com/docker/docker/hosts/state"
)

type DefaultDriver struct{}

func (d *DefaultDriver) DriverName() string {
	return ""
}

func (d *DefaultDriver) SetConfigFromFlags(flagsInterface interface{}) error {
	return nil
}

func (d *DefaultDriver) GetURL() (string, error) {
	url := os.Getenv("DOCKER_HOST")
	if url == "" {
		url = fmt.Sprintf("unix://%s", api.DEFAULTUNIXSOCKET)
	}
	return url, nil
}

func (d *DefaultDriver) GetIP() (string, error) {
	return "", nil
}

func (d *DefaultDriver) GetState() (state.State, error) {
	return state.None, nil
}

func (d *DefaultDriver) Create() error {
	return nil
}

func (d *DefaultDriver) Start() error {
	return fmt.Errorf("default host cannot be started")
}

func (d *DefaultDriver) Stop() error {
	return fmt.Errorf("default host cannot be stopped")
}

func (d *DefaultDriver) Remove() error {
	return fmt.Errorf("default driver cannot be removed")
}

func (d *DefaultDriver) Restart() error {
	return fmt.Errorf("default host cannot be restarted")
}

func (d *DefaultDriver) Kill() error {
	return fmt.Errorf("default host cannot be killed")
}

func (d *DefaultDriver) Upgrade() error {
	return fmt.Errorf("default host cannot be upgraded")
}

func (d *DefaultDriver) GetSSHCommand(args ...string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("default host does not support SSH")
}
