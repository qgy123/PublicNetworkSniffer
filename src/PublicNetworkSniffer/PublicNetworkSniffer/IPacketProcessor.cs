using PcapDotNet.Packets;

namespace PublicNetworkSniffer
{
    public interface IPacketProcessor
    {
        bool IsTargetProtocol(Packet packet);
        void Process(Packet packet);
        string GetProcessorInfo();
    }
}