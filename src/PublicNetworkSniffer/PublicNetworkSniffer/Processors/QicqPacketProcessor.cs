using PcapDotNet.Packets;

namespace PublicNetworkSniffer.Processors
{
    public class QicqPacketProcessor : PacketProcessor
    {
        public override bool IsTargetProtocol(Packet packet)
        {
            return base.IsTargetProtocol(packet);
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