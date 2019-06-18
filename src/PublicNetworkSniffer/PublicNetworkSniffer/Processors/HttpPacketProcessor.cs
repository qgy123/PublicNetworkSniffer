using System;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;

namespace PublicNetworkSniffer.Processors
{
    public class HttpPacketProcessor : PacketProcessor
    {
        public override bool IsTargetProtocol(Packet packet)
        {
            bool? flag = packet.Ethernet?.IpV4?.Protocol == IpV4Protocol.Tcp;
            if ((bool)!flag) return false;

            var portSrc = packet.Ethernet?.IpV4?.Tcp.SourcePort;
            var portDst = packet.Ethernet?.IpV4?.Tcp.DestinationPort;
            return portSrc == 80 || portSrc == 443 || portDst == 80 || portDst == 443;
        }

        public override void Process(Packet packet)
        {
            var http = packet.Ethernet?.IpV4?.Tcp?.Http;
            if (http == null) return;

            if (!http.IsValid || !http.IsRequest) return;
            if (http.Header != null)
                Console.WriteLine($"{GetType().Name}: Http Request: {http.Header}");

        }

        public override string GetProcessorInfo()
        {
            return "Processor To Capture the Http Traffic Information";
        }
    }
}