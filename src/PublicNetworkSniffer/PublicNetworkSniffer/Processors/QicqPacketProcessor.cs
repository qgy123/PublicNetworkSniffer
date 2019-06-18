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
    public class QicqPacketProcessor : PacketProcessor
    {
        public override bool IsTargetProtocol(Packet packet)
        {
            bool? flag = packet.Ethernet?.IpV4?.Protocol == IpV4Protocol.Udp;
            if ((bool)!flag) return false;

            var data = packet.Ethernet?.IpV4?.Udp?.Payload?.ToArray();
            if (data == null) return false;

            //length
            if (!(data.Length >= 28)) return false;

            byte start = data.ReadByte(0);
            byte end = data.ReadByte(data.Length - 1);

            //if (end == 0x03)
            //{
            //    string hex = BitConverter.ToString(data).Replace("-", string.Empty);
            //    Console.WriteLine(hex);
            //}

            return start == 0x02 && end == 0x03;

        }

        public override void Process(Packet packet)
        {
            var data = packet.Ethernet?.IpV4?.Udp?.Payload?.ToMemoryStream();
            if (data == null) return;
            BinaryReader reader = new BinaryReader(data, Encoding.ASCII, false);
            reader.ReadByte();
            var build = reader.ReadInt16().ReverseEndianity();
            var cmd = reader.ReadInt16().ReverseEndianity();
            if (cmd == 0) return;
            var seq = reader.ReadInt16().ReverseEndianity();
            var accountBytes = reader.ReadBytes(4).Reverse();
            long account = BitConverter.ToInt32(accountBytes.ToArray(), 0);
            if (account == 0) return;

            Console.WriteLine(
                $"{GetType().Name}: PCQQ Client Discovered: Client Version:{build} Cmd:{cmd} PacketSeq:{seq} QQ: {account}");
        }

        public override string GetProcessorInfo()
        {
            return "Processor To Capture the QQ packet for Analysis";
        }
    }
}