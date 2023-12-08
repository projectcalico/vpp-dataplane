// Copyright (C) 2023 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/codec"
	"go.fd.io/govpp/core"

	_ "github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/af_packet"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/tapv2"
)

var (
	sockAddr = flag.String("vpp", "", "Path to VPP API socket file")
	infile   = flag.String("file", "", "capture file")
	logLvl   = flag.String("log", "", "log level")

	msgByName        = make(map[string]api.Message)
	msgByTraceID     = make(map[uint32]api.Message)
	msgNameByTraceID = make(map[uint32]string)

	msgCallback MsgCallBack
)

func init() {
	for _, mp := range api.GetRegisteredMessages() {
		for _, msg := range mp {
			msgByName[msg.GetMessageName()] = msg
			logrus.Tracef("loaded msg %s", msg.GetMessageName())
		}
	}
}

func isReply(msg api.Message) bool {
	return strings.HasSuffix(msg.GetMessageName(), "_reply") || strings.HasSuffix(msg.GetMessageName(), "_details")
}

func isDump(msg api.Message) bool {
	if msg.GetMessageName() == "trace_plugin_msg_ids" {
		return true
	}
	return strings.HasSuffix(msg.GetMessageName(), "_dump")
}

func getRetVal(msg api.Message) (err error) {
	if strings.HasSuffix(msg.GetMessageName(), "_reply") {
		if f := reflect.Indirect(reflect.ValueOf(msg)).FieldByName("Retval"); f.IsValid() {
			var retval int32
			switch f.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				retval = int32(f.Int())
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				retval = int32(f.Uint())
			default:
				logrus.Errorf("invalid kind (%v) for Retval field of message %v", f.Kind(), msg.GetMessageName())
			}
			err = api.RetvalToVPPApiError(retval)
		}
	}
	return err
}

func newReplyTypeForRequest(req api.Message) (api.Message, error) {
	reply, found := msgByName[req.GetMessageName()+"_reply"]
	if !found {
		return nil, fmt.Errorf("No reply for %s", req.GetMessageName())
	}
	reply = reflect.New(reflect.TypeOf(reply).Elem()).Interface().(api.Message)
	return reply, nil
}

func sendMsgToVpp(conn api.Connection, msg api.Message) (api.Message, error) {
	if msg == nil || isReply(msg) || isDump(msg) {
		return nil, nil
	}
	logrus.Debugf("Processing %s\n", formatMessage(msg))
	reply, err := newReplyTypeForRequest(msg)
	if err != nil {
		return nil, err
	}
	err = conn.Invoke(context.Background(), msg, reply)
	if err != nil {
		return nil, err
	}
	err = getRetVal(reply)
	if err != nil {
		logrus.Errorf("Error handling %s reply %s err %s\n", formatMessage(msg), formatMessage(reply), err)
		return nil, err
	}
	logrus.Tracef("Reply was %s\n", formatMessage(reply))
	return reply, nil
}

func readMsgData(r io.Reader, dataLen int) ([]byte, error) {
	if dataLen > 8000 {
		return nil, fmt.Errorf("too big dataLen %d", dataLen)
	}
	msg := make([]byte, dataLen, 8000)

	n, err := r.Read(msg)
	if err != nil {
		return nil, err
	}

	if dataLen > n {
		remain := dataLen - n
		view := msg[n:]

		for remain > 0 {
			nbytes, err := r.Read(view)
			if err != nil {
				return nil, err
			} else if nbytes == 0 {
				return nil, fmt.Errorf("zero nbytes")
			}

			remain -= nbytes

			view = view[nbytes:]
		}
	}

	return msg, nil
}

// Format used by the VPP trace (api trace save somefile)
func readVppTraceMsgHeader(r io.Reader) (int, error) {
	header := make([]byte, 4)
	n, err := io.ReadAtLeast(r, header, 4)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	} else if n != 4 {
		return 0, fmt.Errorf("invalid header (expected 4 bytes, got %d)", n)
	}

	dataLen := binary.BigEndian.Uint32(header[0:4])

	return int(dataLen), nil
}

func formatMessage(msg api.Message) string {
	if msg == nil {
		return ""
	}
	js, err := json.Marshal(msg)
	if err != nil {
		logrus.Errorf("Unable to json Marshal message: %v\n", err)
		return ""
	}
	return fmt.Sprintf("{%q:%q, %q:%s}", "name", msg.GetMessageName(), "msg", string(js))
}

func readFileHeaderInt(i *uint32, data []byte) (ret uint32) {
	if data[*i]&1 != 0 {
		ret = uint32(data[*i]) >> 1
		(*i) += 1
		return
	}
	if data[*i]&2 != 0 {
		ret = uint32(binary.LittleEndian.Uint16(data[*i:*i+2]))>>2 + (1 << 7)
		(*i) += 2
		return
	}
	if data[*i]&4 != 0 {
		ret = binary.LittleEndian.Uint32(data[*i:*i+4])>>3 + (1 << 7) + (1 << 14)
		(*i) += 4
		return
	}
	ret = uint32(binary.LittleEndian.Uint64(data[*i+1:*i+9])) + (1 << 7) + (1 << 14)
	(*i) += 9
	return
}

func getMessageNameAndCrc(fullname string) (msgName, crc string) {
	splitted := strings.Split(fullname, "_")
	return strings.Join(splitted[:len(splitted)-1], "_"), splitted[len(splitted)-1]
}

func readFileHeader(r io.Reader) error {
	header := make([]byte, 9)
	_, err := io.ReadAtLeast(r, header, 9)
	if err != nil {
		return err
	}
	// nItems := binary.BigEndian.Uint32(header[0:4])
	tableLen := binary.BigEndian.Uint32(header[4:8])
	msgTable := make([]byte, tableLen)
	_, err = io.ReadAtLeast(r, msgTable, int(tableLen))
	if err != nil {
		return err
	}

	for i := uint32(4); i < tableLen; {
		msgId := readFileHeaderInt(&i, msgTable)
		strl := readFileHeaderInt(&i, msgTable)
		msgName, crc := getMessageNameAndCrc(string(msgTable[i : i+strl]))
		i += strl

		msgNameByTraceID[msgId] = msgName
		apiMsg, found := msgByName[msgName]
		if !found {
			logrus.Tracef("No api Message for %d %s", msgId, msgName)
			continue
		} else {
			logrus.Tracef("Api Message found for %d %s", msgId, msgName)
		}
		if apiMsg.GetCrcString() != crc {
			logrus.Warnf("No api Message CRC does not match for %s", msgName)
			continue
		}
		msgByTraceID[msgId] = apiMsg
	}

	return nil
}

type MsgCallBack interface {
	MsgCallBack(msg api.Message, idx int) error
	Setup()
	TearDown()
}

type MsgCallBackJson struct{}

func (*MsgCallBackJson) MsgCallBack(msg api.Message, idx int) error {
	if idx > 0 {
		fmt.Printf(",")
	}
	fmt.Printf("%s\n", formatMessage(msg))
	return nil
}
func (*MsgCallBackJson) Setup()    { fmt.Printf("[\n") }
func (*MsgCallBackJson) TearDown() { fmt.Printf("]\n") }

func executeShellCommand(cmd string, cmdStr ...string) {
	logrus.Infof("Issuing %s, %s", cmd, cmdStr)
	out, err := exec.Command(cmd, cmdStr...).Output()
	if err != nil {
		logrus.Errorf("error running command %s (%s) %s", cmdStr, out, err)
	}
}

type MsgCallBackVpp struct {
	conn api.Connection
}

func (self *MsgCallBackVpp) MsgCallBack(msg api.Message, idx int) error {
	switch m := msg.(type) {
	case *tapv2.TapCreateV3:
		if m.HostNamespaceSet && !strings.HasPrefix(m.HostNamespace, "pid:") {
			ns := strings.Replace(m.HostNamespace, "/var/run/netns/", "", -1)
			executeShellCommand("ip", "netns", "add", ns)
		}
	case *af_packet.AfPacketCreateV3:
		msg = nil
	default:
	}
	_, err := sendMsgToVpp(self.conn, msg)
	return err
}
func (*MsgCallBackVpp) Setup()    {}
func (*MsgCallBackVpp) TearDown() {}

func main() {
	flag.Parse()
	if *infile == "" {
		logrus.Errorf("Please provide a capture file")
		os.Exit(1)
	}

	if *logLvl != "" {
		lvl, err := logrus.ParseLevel(*logLvl)
		if err != nil {
			panic(err)
		}
		logrus.SetLevel(lvl)
	}

	fi, err := os.Open(*infile)
	if err != nil {
		logrus.Errorf("Could not open file %s %s", *infile, err)
		os.Exit(1)
	}
	defer func() {
		err := fi.Close()
		if err != nil {
			panic(err)
		}
	}()

	err = readFileHeader(fi)
	if err != nil {
		logrus.Errorf("Could not read file %s %s", *infile, err)
		os.Exit(1)
	}

	msgCallback = &MsgCallBackJson{}
	if *sockAddr != "" {
		conn, err := govpp.Connect(*sockAddr)
		if err != nil {
			logrus.Errorf("Could not connect to VPP %s %s", *sockAddr, err)
			os.Exit(1)
		}
		msgCallback = &MsgCallBackVpp{conn}
	}

	msgCallback.Setup()
	for idx := 0; ; idx++ {
		dataLen, err := readVppTraceMsgHeader(fi)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			logrus.Errorf("Could not read VPP trace header from file %s %s", *infile, err)
			os.Exit(1)
		}

		data, err := readMsgData(fi, dataLen)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			logrus.Errorf("Could not read VPP msg data from file %s %s", *infile, err)
			os.Exit(1)
		}

		msgID := uint32(binary.BigEndian.Uint16(data[0:2]))
		msg, found := msgByTraceID[msgID]
		if !found {
			logrus.Errorf("Message not found for ID %d (name=%s)\n", msgID, msgNameByTraceID[msgID])
			continue
		}

		msg = reflect.New(reflect.TypeOf(msg).Elem()).Interface().(api.Message)
		if _, ok := msg.(*core.ControlPing); ok {
			continue
		}

		err = codec.DefaultCodec.DecodeMsg(data, msg)
		if err != nil {
			logrus.Errorf("Unable to decode message: %s %v\n", formatMessage(msg), err)
			continue
		}
		err = msgCallback.MsgCallBack(msg, idx)
		if err != nil {
			logrus.Errorf("Error processing %s %s\n", formatMessage(msg), err)
			return
		}
	}
	msgCallback.TearDown()
}
