# GoFlow2

**NOTE:** this is a fork of [GoFlow2](https://github.com/netsampler/goflow2) that was modified for usage on ShieldWall systems! Only version 1.3.x is meant to be used.

This application is a NetFlow/IPFIX/sFlow collector in Go.

It gathers network information (IP, interfaces, routers) from different flow protocols,
serializes it in a common format.

You will want to use GoFlow if:
* You receive a decent amount of network samples and need horizontal scalability
* Have protocol diversity and need a consistent format
* Require raw samples and build aggregation and custom enrichment

This software is the entry point of a pipeline. The storage, transport, enrichment, graphing, alerting are
not provided.

![GoFlow2 System diagram](/graphics/diagram.png)

## Get started

To read about agents that samples network traffic, check this [page](/docs/agents.md).

To set up the collector, download the latest release corresponding to your OS
and run the following command (the binaries have a suffix with the version):

```bash
$ ./goflow2
```

By default, this command will launch an sFlow collector on port `:6343` and
a NetFlowV9/IPFIX collector on port `:2055`.

By default, the samples received will be printed in JSON format on the stdout.

```json
{
  "Type": "SFLOW_5",
  "TimeFlowEnd": 1621820000,
  "TimeFlowStart": 1621820000,
  "TimeReceived": 1621820000,
  "Bytes": 70,
  "Packets": 1,
  "SamplingRate": 100,
  "SamplerAddress": "192.168.1.254",
  "DstAddr": "10.0.0.1",
  "DstMac": "ff:ff:ff:ff:ff:ff",
  "SrcAddr": "192.168.1.1",
  "SrcMac": "ff:ff:ff:ff:ff:ff",
  "InIf": 1,
  "OutIf": 2,
  "Etype": 2048,
  "EtypeName": "IPv4",
  "Proto": 6,
  "ProtoName": "TCP",
  "SrcPort": 443,
  "DstPort": 46344,
  "FragmentId": 54044,
  "FragmentOffset": 16384,
  ...
  "IPTTL": 64,
  "IPTos": 0,
  "TCPFlags": 16,
}
```

If you are using a log integration (e.g: Loki with Promtail, Splunk, Fluentd, Google Cloud Logs, etc.),
just send the output into a file.
```bash
$ ./goflow2 -transport.file /var/logs/goflow2.log
```

You can filter the output using the `-format.selector` flag. Only the listed fields will be forwarded:


```bash
$ ./goflow2 -format.selector TimeReceived,TimeFlowStartMs,TimeFlowEndMs,Bytes,EtypeName,ProtoName,SrcAddr,DstAddr,SrcPort,DstPort
```

This also allows you to add some additional fields:

  * EtypeName
  * ProtoName
  * IcmpName
  * TcpFlagsName
  * FlowDirectionName (_in/out_)
  * FlowTypeName (_only if flow source is localhost; inbound/outbound/forward_)
  * InIfName (_only if flow source is localhost_)
  * OutIfName (_only if flow source is localhost_)

## License

Licensed under the BSD-3 License.
