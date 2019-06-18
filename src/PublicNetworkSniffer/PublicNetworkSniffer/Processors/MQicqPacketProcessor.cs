using System;
using System.IO;
using System.Linq;
using System.Text;
using PcapDotNet.Base;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using Syroot.BinaryData;

namespace PublicNetworkSniffer.Processors
{
    public class MQicqPacketProcessor : PacketProcessor
    {
        public override bool IsTargetProtocol(Packet packet)
        {
            bool? flag = packet.Ethernet?.IpV4?.Protocol == IpV4Protocol.Tcp;
            if ((bool)!flag) return false;

            var portSrc = packet.Ethernet?.IpV4?.Tcp.SourcePort;
            var portDst = packet.Ethernet?.IpV4?.Tcp.DestinationPort;
            if (IsMQQPort((int) portSrc) && IsMQQPort((int) portDst))
                return false;

            var data = packet.Ethernet?.IpV4?.Tcp?.Payload?.ToArray();
            if (data == null) return false;

            if (!(data.Length >= 40)) return false;

            var start = data.ReadShort(0, Endianity.Big);
            return start == 0;

        }

        public override void Process(Packet packet)
        {
            var data = packet.Ethernet?.IpV4?.Tcp?.Payload?.ToMemoryStream();
            if (data == null) return;
            BinaryReader reader = new BinaryReader(data, Encoding.ASCII, false);

            reader.ReadInt16(); //00 00
            var len = reader.ReadInt16().ReverseEndianity(); //00 5A

            reader.ReadUInt32();

            var encType = reader.ReadByte(); //00 01 02

            var skipBytes = reader.ReadBytes(4).Reverse();
            var skip = BitConverter.ToInt32(skipBytes.ToArray(), 0);

            if (skip >= 12) return;

            reader.ReadBytes(skip);

            var accountLen = reader.ReadByte();

            if (accountLen >= 9 && accountLen <=16)
            {
                var account = new string(reader.ReadChars(accountLen - 4));

                Console.WriteLine(
                    $"{GetType().Name}: MQQ Client Discovered: EncType:{encType} QQ: {account}");
            }

        }

        private bool IsMQQPort(int port)
        {
            return port != 80 && port != 443 && port != 8080 && port != 14000 && port != 15000;
        }

        public override string GetProcessorInfo()
        {
            return "Processor To Capture the MQQ packet for Analysis";
        }
    }
}