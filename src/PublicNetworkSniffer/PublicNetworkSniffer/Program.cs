using ConsoleTables;
using PcapDotNet.Core;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Reflection;
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
        //private static DateTime _lastTimestamp;
        private static List<PacketProcessor> _processors = new List<PacketProcessor>();
        static void Main(string[] args)
        {
            ShowInfo();

            LoadProcessors();

            ShowDeviceList();

            AskForInterfaceSelection();

            StartSniffing();
        }

        static void ShowInfo()
        {
            Console.WriteAscii("Network Sniffer", Color.Gold);
            Console.WriteLine();
            Console.WriteWithGradient("Please Select Your NetWork Interface", Color.Red, Color.Magenta, 12);
            Console.ReplaceAllColorsWithDefaults();
            Console.WriteLine();
            Console.WriteLine();
        }

        static void LoadProcessors()
        {
            var a = Assembly.GetExecutingAssembly().GetTypes();
            int sum = 0;

            foreach (var type in a)
            {
                try
                {
                    if (type.Namespace == MethodBase.GetCurrentMethod().DeclaringType.Namespace + ".Processors")
                    {
                        if (type.FullName == null) continue;
                        var t = Type.GetType(type.FullName);
                        var p = Activator.CreateInstance(t);
                        if (p is PacketProcessor pp)
                        {
                            _processors.Add(pp);
                        }
                        sum++;
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("Fail to load processor:" + type.FullName, Color.Red);
                }
            }

            Console.WriteLine($"{sum} Protocol Processors Loaded!", Color.Gold);
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

            Console.WriteLine(table.ToString(), Color.White);
            Console.WriteLine(table2.ToString(), Color.White);

            Console.WriteLine();
        }

        static void AskForInterfaceSelection()
        {
            Console.WriteLine("Your Selection  (1-" + _allDevices.Count + "):", Color.DeepSkyBlue);
            Console.ForegroundColor = Color.White;

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
                //using (BerkeleyPacketFilter filter = communicator.CreateFilter("udp"))
                //{
                //    communicator.SetFilter(filter);
                //}
                communicator.ReceivePackets(0, PacketHandler);
            }

        }

        private static void PacketHandler(Packet packet)
        {
            if (!packet.IsValid) return;

            foreach (var processor in _processors)
            {
                try
                {
                    var flag = processor.IsTargetProtocol(packet);
                    if (!flag) continue;
                    processor.Process(packet);
                }
                catch (Exception)
                {
                    Console.WriteLine(processor.GetType().Name + ": Occured a problem!", Color.Red);
                }
            }
        }

    }
}
