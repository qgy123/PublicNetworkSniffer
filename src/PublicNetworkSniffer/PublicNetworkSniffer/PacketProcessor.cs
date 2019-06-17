using System.Drawing;
using Colorful;
using PcapDotNet.Packets;

namespace PublicNetworkSniffer
{
    public class PacketProcessor : IPacketProcessor
    {
        /// <summary>
        /// Is current packet match the protocol
        /// </summary>
        /// <param name="packet"></param>
        /// <returns></returns>
        public virtual bool IsTargetProtocol(Packet packet) => true;

        /// <summary>
        /// If protocol match, process will be invoke
        /// </summary>
        /// <param name="packet"></param>
        public virtual void Process(Packet packet)
        {
            Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length + " Src:" + packet.IpV4.Source + " Dst:" + packet.IpV4.Destination, Color.Green);
        }

        public virtual string GetProcessorInfo() => "Default processor";
    }
}