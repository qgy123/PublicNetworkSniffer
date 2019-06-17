using System.IO;
using System.Linq;
using PcapDotNet.Packets;
using Syroot.BinaryData;

namespace PublicNetworkSniffer.Processors
{
    public class QicqPacketProcessor : PacketProcessor
    {
        public override bool IsTargetProtocol(Packet packet)
        {
            var data = packet.IpV4.Payload.ToMemoryStream();
            BinaryReader reader = new BinaryReader(data);
            byte start = reader.ReadByte();
            byte end = 0;
            while (!data.IsEndOfStream()) { end = reader.ReadByte(); }

            return start == (byte)0x02 && end == (byte)0x03;
        }

        public override void Process(Packet packet)
        {
            base.Process(packet);
        }

        public override string GetProcessorInfo()
        {
            return base.GetProcessorInfo();
        }
    }
}