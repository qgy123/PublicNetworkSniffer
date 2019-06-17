using ConsoleTables;
using PcapDotNet.Core;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Packets;
using Console = Colorful.Console;

namespace PublicNetworkSniffer
{
    class Program
    {
        private static IList<LivePacketDevice> _allDevices;
        private static PacketDevice _selectedDevice;
        private static DateTime _lastTimestamp;

        static void Main(string[] args)
        {
            ShowInfo();

            ShowDeviceList();

            AskForInterfaceSelection();

            StartSniffing();

            Console.ReadLine();
        }

        static void ShowInfo()
        {
            Console.WriteAscii("Network Sniffer", Color.Green);
            Console.WriteLine();
            Console.WriteWithGradient("Please Select Your NetWork Interface", Color.Red, Color.Magenta, 12);
            Console.WriteLine();
            Console.WriteLine();
            Console.ReplaceAllColorsWithDefaults();

        }

        static void ShowDeviceList()
        {
            _allDevices = LivePacketDevice.AllLocalMachine;

            if (_allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.", Color.Red);
                Console.ReadLine();
                return;
            }

            var table = new ConsoleTable("No", "Device Name", "Device Description");
            var table2 = new ConsoleTable("No", "Family", "Address", "Netmask", "Broadcast Address", "Dst Address");
            // Print the list
            for (int i = 0; i != _allDevices.Count; ++i)
            {
                LivePacketDevice device = _allDevices[i];
                table.AddRow(i + 1, device.Name, device.Description ?? "No description");

                foreach (DeviceAddress address in device.Addresses)
                {
                    table2.AddRow("", "", "", "", "", "");
                    int last = table2.Rows.Count - 1;
                    table2.Rows[last][0] = i + 1;

                    table2.Rows[last][1] = address.Address.Family;

                    if (address.Address != null)
                        table2.Rows[last][2] = address.Address;
                    if (address.Netmask != null)
                        table2.Rows[last][3] = address.Netmask;
                    if (address.Broadcast != null)
                        table2.Rows[last][4] = address.Broadcast;
                    if (address.Destination != null)
                        table2.Rows[last][5] = address.Destination;
                }

            }

            table.Write();
            table2.Write();

            Console.WriteLine();
        }

        static void AskForInterfaceSelection()
        {
            Console.WriteLine("Your Selection  (1-" + _allDevices.Count + "):", Color.DeepSkyBlue);

            int deviceIndex = 0;

            do
            {
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > _allDevices.Count)
                {
                    Console.WriteLine("Invalid Input!", Color.Crimson);
                }
                else
                {
                    break;
                }

            } while (true);

            _selectedDevice = _allDevices[deviceIndex - 1];
        }

        static void StartSniffing()
        {
            using (PacketCommunicator communicator = _selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                Console.WriteLine("Listening on " + _selectedDevice.Description + "...", Color.Coral);
                communicator.ReceivePackets(0, PacketHandler);
            }

        }

        private static void PacketHandler(Packet packet)
        {

        }

    }
}
