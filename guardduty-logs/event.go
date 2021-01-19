package guarddutylogs

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"strings"
)

// LogEntry is a flattened version of the guardduty.Finding that is more friendly for log processing
type LogEntry struct {
	// Common attributes, should exist in every event:
	AccountId    string  `json:"account_id,omitempty"`
	Arn          string  `json:"arn,omitempty"`
	CreatedAt    string  `json:"created_at,omitempty"`
	Description  string  `json:"description,omitempty"`
	Id           string  `json:"id,omitempty"`
	Partition    string  `json:"partition,omitempty"`
	Region       string  `json:"region,omitempty"`
	Severity     float64 `json:"severity,omitempty"`
	Title        string  `json:"title,omitempty"`
	EventType    string  `json:"event_type,omitempty"`
	UpdatedAt    string  `json:"updated_at,omitempty"`
	ResourceType string  `json:"resource_type,omitempty"`

	// InstanceDetails Resource
	InstanceAz         string            `json:"instance_az,omitempty"`
	InstanceDesc       string            `json:"instance_desc,omitempty"`
	InstanceImageId    string            `json:"instance_image_id,omitempty"`
	InstanceId         string            `json:"instance_id,omitempty"`
	InstanceState      string            `json:"instance_state,omitempty"`
	InstanceType       string            `json:"instance_type,omitempty"`
	InstanceLaunchTime string            `json:"instance_launch_time,omitempty"`
	InstancePrivateIp  []string          `json:"instance_private_ip,omitempty"`
	InstancePublicIp   []string          `json:"instance_public_ip,omitempty"`
	InstanceSubnet     []string          `json:"instance_subnet,omitempty"`
	InstanceVpc        string            `json:"instance_vpc,omitempty"`
	InstanceSg         map[string]string `json:"instance_sg,omitempty"`
	InstanceTags       map[string]string `json:"instance_tags,omitempty"`

	// AccessKeyDetails Resource
	AccessKeyId string `json:"access_key_id,omitempty"`
	PrincipalId string `json:"principal_id,omitempty"`
	UserName    string `json:"username,omitempty"`
	UserType    string `json:"user_type,omitempty"`

	// Common values for Action
	// can be multiple actions in a single finding, should loop and create unique event for each:
	Archived       bool     `json:"archived,omitempty"`
	DetectorId     string   `json:"detector_id,omitempty"`
	Count          int64    `json:"count"`
	EventFirstSeen string   `json:"event_first_seen,omitempty"`
	EventLastSeen  string   `json:"event_last_seen,omitempty"`
	ResourceRole   string   `json:"resource_role,omitempty"`
	ServiceName    string   `json:"service_name,omitempty"`
	UserFeedBack   string   `json:"user_feed_back,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
	ActionType     string   `json:"action_type,omitempty"`

	// AwsApiCallAction
	Api            string `json:"api,omitempty"`
	CallerType     string `json:"caller_type,omitempty"`
	Domain         string `json:"domain,omitempty"`
	ApiServiceName string `json:"service_name,omitempty"`

	// DnsRequestAction
	DnsDomain string `json:"dns_domain,omitempty"`

	// PortProbeAction
	PortProbeBLocked bool   `json:"port_probe_b_locked,omitempty"`
	Port             int64  `json:"port,omitempty"`
	PortName         string `json:"port_name,omitempty"`

	// NetworkConnectionAction
	ConnectionBlocked   bool   `json:"connection_blocked,omitempty"`
	ConnectionDirection string `json:"connection_direction,omitempty"`
	ConnectionProtocol  string `json:"connection_protocol,omitempty"`

	// LocalPortDetails can be shared across ActionTypes
	DestPort     int64  `json:"dest_port,omitempty"`
	DestPortName string `json:"dest_port_name,omitempty"`

	// RemotePortDetails ... also shared
	SrcPort     int64  `json:"src_port,omitempty"`
	SrcPortName string `json:"src_port_name,omitempty"`

	// RemoteIpDetails can be shared across ActionTypes
	SrcIp        string  `json:"src_ip,omitempty"`
	SrcIpCity    string  `json:"src_ip_city,omitempty"`
	SrcIpCountry string  `json:"src_ip_country,omitempty"`
	SrcIpLat     float64 `json:"src_ip_lat,omitempty"`
	SrcIpLon     float64 `json:"src_ip_long,omitempty"`
	SrcIpAsn     string  `json:"src_ip_org_asn,omitempty"`
	SrcIpOrg     string  `json:"src_ip_org,omitempty"`
	SrcIpIsp     string  `json:"src_ip_isp,omitempty"`
}

// addCommon populates information present in every finding
func (l *LogEntry) addCommon(f *guardduty.Finding) {
	l.AccountId = aws.StringValue(f.AccountId)
	l.Arn = aws.StringValue(f.Arn)
	l.CreatedAt = aws.StringValue(f.CreatedAt)
	l.Description = aws.StringValue(f.Description)
	l.Id = aws.StringValue(f.Id)
	l.Partition = aws.StringValue(f.Partition)
	l.Region = aws.StringValue(f.Region)
	l.Severity = aws.Float64Value(f.Severity)
	l.Title = aws.StringValue(f.Title)
	l.EventType = aws.StringValue(f.Type)
	l.UpdatedAt = aws.StringValue(f.UpdatedAt)
	l.ResourceType = aws.StringValue(f.Resource.ResourceType)

}

// addCommonService populates information present in every action
func (l *LogEntry) addCommonService(a *guardduty.Service) {
	l.Archived = aws.BoolValue(a.Archived)
	l.DetectorId = aws.StringValue(a.DetectorId)
	l.Count = aws.Int64Value(a.Count)
	l.EventFirstSeen = aws.StringValue(a.EventFirstSeen)
	l.EventLastSeen = aws.StringValue(a.EventLastSeen)
	l.ResourceRole = aws.StringValue(a.ResourceRole)
	l.ServiceName = aws.StringValue(a.ServiceName)
	l.UserFeedBack = aws.StringValue(a.UserFeedback)
	l.ActionType = aws.StringValue(a.Action.ActionType)
	if a.Evidence != nil {
		for _, ti := range a.Evidence.ThreatIntelligenceDetails {
			names := make([]string, 0)
			for _, n := range ti.ThreatNames {
				names = append(names, aws.StringValue(n))
			}
			threats := strings.Join(names, ",")
			l.Evidence = append(
				l.Evidence,
				aws.StringValue(ti.ThreatListName)+": "+threats,
			)
		}
	}
}

// addInstance populates information about the instance in a finding.
func (l *LogEntry) addInstance(i *guardduty.InstanceDetails) {
	l.InstanceAz = aws.StringValue(i.AvailabilityZone)
	l.InstanceDesc = aws.StringValue(i.ImageDescription)
	l.InstanceImageId = aws.StringValue(i.ImageId)
	l.InstanceId = aws.StringValue(i.InstanceId)
	l.InstanceState = aws.StringValue(i.InstanceState)
	l.InstanceType = aws.StringValue(i.InstanceType)
	l.InstanceLaunchTime = aws.StringValue(i.LaunchTime)
	l.InstanceTags = make(map[string]string)
	for _, t := range i.Tags {
		l.InstanceTags[aws.StringValue(t.Key)] = aws.StringValue(t.Value)
	}
	// build list of public, private IP's and subnets:
	l.InstanceSg = make(map[string]string)
	prv := make(map[string]bool)
	pub := make(map[string]bool)
	sub := make(map[string]bool)
	for _, in := range i.NetworkInterfaces {
		prv[aws.StringValue(in.PrivateIpAddress)] = true
		for _, ip := range in.PrivateIpAddresses {
			prv[aws.StringValue(ip.PrivateIpAddress)] = true
		}
		pub[aws.StringValue(in.PublicIp)] = true
		sub[aws.StringValue(in.SubnetId)] = true
		l.InstanceVpc = aws.StringValue(in.VpcId)
		for _, sg := range in.SecurityGroups {
			l.InstanceSg[aws.StringValue(sg.GroupId)] = aws.StringValue(sg.GroupName)
		}
	}
	for k := range prv {
		l.InstancePrivateIp = append(l.InstancePrivateIp, k)
	}
	for k := range pub {
		l.InstancePublicIp = append(l.InstancePublicIp, k)
	}
	for k := range sub {
		l.InstanceSubnet = append(l.InstanceSubnet, k)
	}
}

// addAccessKey populates information about the access key used in a finding.
func (l *LogEntry) addAccessKey(k *guardduty.AccessKeyDetails) {
	l.AccessKeyId = aws.StringValue(k.AccessKeyId)
	l.PrincipalId = aws.StringValue(k.PrincipalId)
	l.UserName = aws.StringValue(k.UserName)
	l.UserType = aws.StringValue(k.UserType)
}

// addApiCall populates information about api call causing an alert
func (l *LogEntry) addApiCall(a *guardduty.AwsApiCallAction) {
	l.Api = aws.StringValue(a.Api)
	l.CallerType = aws.StringValue(a.CallerType)
	if a.DomainDetails != nil && a.DomainDetails.Domain != nil {
		l.Domain = aws.StringValue(a.DomainDetails.Domain)
	}
	l.ApiServiceName = aws.StringValue(a.ServiceName)
	l.SrcIp = aws.StringValue(a.RemoteIpDetails.IpAddressV4)
	l.SrcIpCity = aws.StringValue(a.RemoteIpDetails.City.CityName)
	l.SrcIpCountry = aws.StringValue(a.RemoteIpDetails.Country.CountryName)
	l.SrcIpLat = aws.Float64Value(a.RemoteIpDetails.GeoLocation.Lat)
	l.SrcIpLon = aws.Float64Value(a.RemoteIpDetails.GeoLocation.Lon)
	l.SrcIpAsn = aws.StringValue(a.RemoteIpDetails.Organization.Asn)
	l.SrcIpIsp = aws.StringValue(a.RemoteIpDetails.Organization.Isp)
	l.SrcIpOrg = aws.StringValue(a.RemoteIpDetails.Organization.Org)
}

// addDns populates information about suspicious DNS request
func (l *LogEntry) addDns(d *guardduty.DnsRequestAction) {
	l.DnsDomain = aws.StringValue(d.Domain)
}

// addPortProbe populates information about incoming network attacks
func (l *LogEntry) addPortProbe(p *guardduty.PortProbeAction, d *guardduty.PortProbeDetail) {
	l.PortProbeBLocked = aws.BoolValue(p.Blocked)
	l.DestPort = aws.Int64Value(d.LocalPortDetails.Port)
	l.DestPortName = aws.StringValue(d.LocalPortDetails.PortName)
	l.Port = aws.Int64Value(d.LocalPortDetails.Port)
	l.PortName = aws.StringValue(d.LocalPortDetails.PortName)
	l.SrcIp = aws.StringValue(d.RemoteIpDetails.IpAddressV4)
	l.SrcIpCity = aws.StringValue(d.RemoteIpDetails.City.CityName)
	l.SrcIpCountry = aws.StringValue(d.RemoteIpDetails.Country.CountryName)
	l.SrcIpLat = aws.Float64Value(d.RemoteIpDetails.GeoLocation.Lat)
	l.SrcIpLon = aws.Float64Value(d.RemoteIpDetails.GeoLocation.Lon)
	l.SrcIpAsn = aws.StringValue(d.RemoteIpDetails.Organization.Asn)
	l.SrcIpIsp = aws.StringValue(d.RemoteIpDetails.Organization.Isp)
	l.SrcIpOrg = aws.StringValue(d.RemoteIpDetails.Organization.Org)
}

// addConnection populates information about suspicious outgoing network activity
func (l *LogEntry) addConnection(c *guardduty.NetworkConnectionAction) {
	l.ConnectionBlocked = aws.BoolValue(c.Blocked)
	l.ConnectionDirection = aws.StringValue(c.ConnectionDirection)
	l.ConnectionProtocol = aws.StringValue(c.Protocol)
	l.DestPort = aws.Int64Value(c.LocalPortDetails.Port)
	l.DestPortName = aws.StringValue(c.LocalPortDetails.PortName)
	l.Port = aws.Int64Value(c.LocalPortDetails.Port)
	l.PortName = aws.StringValue(c.LocalPortDetails.PortName)
	l.SrcIp = aws.StringValue(c.RemoteIpDetails.IpAddressV4)
	l.SrcIpCity = aws.StringValue(c.RemoteIpDetails.City.CityName)
	l.SrcIpCountry = aws.StringValue(c.RemoteIpDetails.Country.CountryName)
	l.SrcIpLat = aws.Float64Value(c.RemoteIpDetails.GeoLocation.Lat)
	l.SrcIpLon = aws.Float64Value(c.RemoteIpDetails.GeoLocation.Lon)
	l.SrcIpAsn = aws.StringValue(c.RemoteIpDetails.Organization.Asn)
	l.SrcIpIsp = aws.StringValue(c.RemoteIpDetails.Organization.Isp)
	l.SrcIpOrg = aws.StringValue(c.RemoteIpDetails.Organization.Org)
}

// NewLogs manipulates a guardduty.Finding into flat structs, and if there are multiple events in the finding
// returns multiple LogEntry records to denormalize the events into discrete logs.
func NewLogs(finding *guardduty.Finding) (logs []LogEntry, err error) {
	switch aws.StringValue(finding.Service.Action.ActionType) {
	// if this is a port-probe, it can have multiple events in a single record, so we add a new log for each.
	case "PORT_PROBE":
		for _, probe := range finding.Service.Action.PortProbeAction.PortProbeDetails {
			l := LogEntry{}
			l.addCommon(finding)
			l.addInstance(finding.Resource.InstanceDetails)
			l.addCommonService(finding.Service)
			l.addPortProbe(finding.Service.Action.PortProbeAction, probe)
			logs = append(logs, l)
		}
	case "NETWORK_CONNECTION":
		l := LogEntry{}
		l.addCommon(finding)
		if finding.Resource != nil && finding.Resource.InstanceDetails != nil {
			l.addInstance(finding.Resource.InstanceDetails)
		}
		if finding.Service != nil {
			l.addCommonService(finding.Service)
		}
		l.addConnection(finding.Service.Action.NetworkConnectionAction)
		logs = append(logs, l)
	case "DNS_REQUEST":
		l := LogEntry{}
		l.addCommon(finding)
		if finding.Resource != nil && finding.Resource.InstanceDetails != nil {
			l.addInstance(finding.Resource.InstanceDetails)
		}
		if finding.Service != nil {
			l.addCommonService(finding.Service)
		}
		l.addDns(finding.Service.Action.DnsRequestAction)
		logs = append(logs, l)
	case "AWS_API_CALL":
		l := LogEntry{}
		l.addCommon(finding)
		if finding.Service != nil {
			l.addCommonService(finding.Service)
		}
		l.addApiCall(finding.Service.Action.AwsApiCallAction)
		logs = append(logs, l)
	}
	return
}

func ParseEvent(ev *json.RawMessage) (*guardduty.Finding, error) {
	// can't directly cast to guardduty.Finding type, have to roundtrip via marshalling :(
	j, _ := ev.MarshalJSON()
	finding := &guardduty.Finding{}
	err := json.Unmarshal(j, finding)
	if err != nil {
		return nil, err
	}
	return finding, nil
}
