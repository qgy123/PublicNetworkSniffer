namespace PublicNetworkSniffer
{
    public class ProtocolStatistic
    {
        public int TotalPackets
        {
            get => totalPackets;
            set => totalPackets = value;
        }

        public int TotalIn
        {
            get => totalIn;
            set => totalIn = value;
        }

        public int TotalOut
        {
            get => totalOut;
            set => totalOut = value;
        }

        private int totalPackets;
        private int totalIn;
        private int totalOut;
    }
}