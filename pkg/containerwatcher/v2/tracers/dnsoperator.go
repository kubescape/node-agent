package tracers

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

func NewDnsOperator() operators.DataOperator {
	return simple.New("dns",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			ds, ok := gadgetCtx.GetDataSources()["dns"]
			if !ok {
				return fmt.Errorf("dns datasource not found")
			}

			dataF := ds.GetField("data")
			lenF := ds.GetField("data_len")
			dnsOffF := ds.GetField("dns_off")

			idF, err := ds.AddField("id", api.Kind_String)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			qrRawF, err := ds.AddField("qr_raw", api.Kind_Bool)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			qrF, err := ds.AddField("qr", api.Kind_String)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			qtypeRawF, err := ds.AddField("qtype_raw", api.Kind_Uint16)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			qtypeF, err := ds.AddField("qtype", api.Kind_String)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			nameF, err := ds.AddField("name", api.Kind_String)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			rcodeRawF, err := ds.AddField("rcode_raw", api.Kind_Uint16)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			rcodeF, err := ds.AddField("rcode", api.Kind_String)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			numAnswersF, err := ds.AddField("num_answers", api.Kind_Int32)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			addressesF, err := ds.AddField("addresses", api.Kind_String)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			TruncatedF, err := ds.AddField("tc", api.Kind_Bool)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			RecursionAvailableF, err := ds.AddField("ra", api.Kind_Bool)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			RecursionDesiredF, err := ds.AddField("rd", api.Kind_Bool)
			if err != nil {
				return fmt.Errorf("failed to add field: %s", err)
			}

			dataFunc := func(source datasource.DataSource, data datasource.Data) error {
				// Get all fields sent by ebpf
				payloadLen, err := lenF.Uint32(data)
				if err != nil {
					return fmt.Errorf("failed to get data_len: %s", err)
				}
				dnsOff, err := dnsOffF.Uint16(data)
				if err != nil {
					return fmt.Errorf("failed to get dns_off: %s", err)
				}

				if payloadLen < uint32(dnsOff) {
					return fmt.Errorf("packet too short: dataLen: %d < dnsOff: %d", payloadLen, dnsOff)
				}

				payload, err := dataF.Bytes(data)
				if err != nil {
					return fmt.Errorf("failed to get data: %s", err)
				}

				if len(payload) == 0 {
					return fmt.Errorf("empty data")
				}

				msg := dnsmessage.Message{}
				if err := msg.Unpack(payload[dnsOff:]); err != nil {
					return fmt.Errorf("failed to unpack dns message: %s", err)
				}

				idF.PutString(data, fmt.Sprintf("%.4x", msg.ID))

				qrRawF.PutBool(data, msg.Header.Response)
				if msg.Header.Response {
					rcodeRawF.PutUint16(data, uint16(msg.Header.RCode))
					rcodeF.PutString(data, RCode(msg.Header.RCode).String())
					qrF.PutString(data, "R")
				} else {
					qrF.PutString(data, "Q")
				}

				TruncatedF.PutBool(data, msg.Header.Truncated)

				RecursionAvailableF.PutBool(data, msg.Header.RecursionAvailable)

				RecursionDesiredF.PutBool(data, msg.Header.RecursionDesired)

				if len(msg.Questions) > 0 {
					question := msg.Questions[0]
					qtypeRawF.PutUint16(data, uint16(question.Type))
					qtypeF.PutString(data, Type(question.Type).String())
					nameF.PutString(data, question.Name.String())
				}

				numAnswersF.PutInt32(data, int32(len(msg.Answers)))

				var addresses []string

				for _, answer := range msg.Answers {
					var str string
					switch answer.Header.Type {
					case dnsmessage.TypeA:
						ipv4 := answer.Body.(*dnsmessage.AResource)
						str = net.IP(ipv4.A[:]).String()
					case dnsmessage.TypeAAAA:
						ipv6 := answer.Body.(*dnsmessage.AAAAResource)
						str = net.IP(ipv6.AAAA[:]).String()
					}
					if str != "" {
						addresses = append(addresses, str)
					}
				}

				addressesF.PutString(data, strings.Join(addresses, ","))
				return nil
			}

			return ds.Subscribe(dataFunc, 0)
		}),
		simple.WithPriority(1),
	)
}

/// Some helpers

// Taken from
// https://cs.opensource.google/go/x/net/+/refs/tags/v0.27.0:dns/dnsmessage/message.go
// to trim Type and Rcode prefixes.
// More information about the DNS message format can be found in
// https://datatracker.ietf.org/doc/html/rfc1035 and
// https://datatracker.ietf.org/doc/html/rfc3596.

// A Type is a type of DNS request and response.
type Type uint16

const (
	// ResourceHeader.Type and Question.Type
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeOPT   Type = 41

	// Question.Type
	TypeWKS   Type = 11
	TypeHINFO Type = 13
	TypeMINFO Type = 14
	TypeAXFR  Type = 252
	TypeALL   Type = 255
)

var typeNames = map[Type]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeSOA:   "SOA",
	TypePTR:   "PTR",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
	TypeSRV:   "SRV",
	TypeOPT:   "OPT",
	TypeWKS:   "WKS",
	TypeHINFO: "HINFO",
	TypeMINFO: "MINFO",
	TypeAXFR:  "AXFR",
	TypeALL:   "ALL",
}

// String implements fmt.Stringer.String.
func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("%d", t)
}

// An RCode is a DNS response status code.
type RCode uint16

// Header.RCode values.
const (
	RCodeSuccess        RCode = 0 // NoError
	RCodeFormatError    RCode = 1 // FormErr
	RCodeServerFailure  RCode = 2 // ServFail
	RCodeNameError      RCode = 3 // NXDomain
	RCodeNotImplemented RCode = 4 // NotImp
	RCodeRefused        RCode = 5 // Refused
)

var rCodeNames = map[RCode]string{
	RCodeSuccess:        "Success",
	RCodeFormatError:    "FormatError",
	RCodeServerFailure:  "ServerFailure",
	RCodeNameError:      "NameError",
	RCodeNotImplemented: "NotImplemented",
	RCodeRefused:        "Refused",
}

// String implements fmt.Stringer.String.
func (r RCode) String() string {
	if n, ok := rCodeNames[r]; ok {
		return n
	}
	return fmt.Sprintf("%d", r)
}
