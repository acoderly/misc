package main

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"time"

	"github.com/golang/glog"
	goexpect "github.com/google/goexpect"
	ssh "github.com/melbahja/goph"
)

const (
	timeout = 10 * time.Minute
	command = `qemu-system-i386 -m 1G -hda /home/orcsir/download/x86_disk.qcow2 -device e1000,netdev=nic1 -netdev user,id=nic1,hostfwd=tcp:127.0.0.1:9527-:22 -monitor stdio
	`
	bash_cmd = "sshpass -p \"1qazXSW@\" ssh -p 9527 root@127.0.0.1 \"uname -a\""
)

var qemuRE = regexp.MustCompile(`(qemu).*`)

func check_vm_is_ok(bashcmd string) error {
	output, err := exec.Command("bash", "-c", bash_cmd).Output()
	if err != nil || len(output) < 10 {
		return errors.New("VM is not ready")
	}
	return nil
}

func uploadFileBySSH(file_local_path, file_remote_dir string) error {
	auth := ssh.Password("1qazXSW@")
	client, err := ssh.New("root", "127.0.0.1", auth)
	if err != nil {
		return errors.New("can not create ssh connection")
	}
	defer client.Close()

	if err := client.Upload(file_local_path, file_remote_dir); err != nil {
		return errors.New("can not uplpad file")
	}
	return nil
}

func runCommandOnVM(command string) (output string, err error) {
	auth := ssh.Password("1qazXSW@")
	client, err := ssh.New("root", "127.0.0.1", auth)
	if err != nil {
		return "", errors.New("can not create ssh connection")
	}
	defer client.Close()

	outer, err := client.Run(command)
	if err != nil {
		return "", errors.New("can not run file on vm")
	}
	return string(outer), nil
}

func downloadFileFromVM(file_remote_path, file_local_path string) (err error) {
	auth := ssh.Password("1qazXSW@")
	client, err := ssh.New("root", "127.0.0.1", auth)
	if err != nil {
		return errors.New("can not create ssh connection")
	}
	defer client.Close()

	if err := client.Download(file_remote_path, file_local_path); err != nil {
		return errors.New("can not download file")
	}
	return nil
}

func main() {
	child, _, err := goexpect.Spawn(command, timeout)
	if err != nil {
		glog.Exit(err)
	}
	defer func() {
		if err := child.Close(); err != nil {
			glog.Infof("Close failed: %v", err)
		}
	}()

	fmt.Println("Spawn qemu success.")

	if err := child.Send("loadvm init" + "\n"); err != nil {
		glog.Exit(err)
	}

	fmt.Println("Loadvm init success.")

	if _, _, err := child.Expect(qemuRE, timeout); err != nil {
		glog.Exit(err)
	}

	if err := check_vm_is_ok(bash_cmd); err != nil {
		glog.Exit("VM is not ready.", err)
	}

	fmt.Println("VM is ready.")

	if err := uploadFileBySSH("./ev.sh", "/tmp/ev.sh"); err != nil {
		glog.Exit("Can not update to vm.", err)
	}

	if err := uploadFileBySSH("./cmd.sh", "/tmp/cmd.sh"); err != nil {
		glog.Exit("Can not update to vm.", err)
	}
	if _, err := runCommandOnVM("nohup /bin/bash /tmp/cmd.sh > /dev/null 2>&1 &"); err != nil {
		glog.Exit("Can not execute command on vm.", err)
	}

	time.Sleep(10 * time.Second)

	if err := downloadFileFromVM("/tmp/strace.out", "./strace.out"); err != nil {
		glog.Exit("Can not execute command on vm.", err)
	}
	if err := child.Send("quit" + "\n"); err != nil {
		glog.Exit(err)
	}
	fmt.Println("Send quit success.")

	fmt.Println("Over")

}
