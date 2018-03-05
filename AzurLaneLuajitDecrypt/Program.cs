using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AzurLaneLuajitDecrypt
{
    static class Program
    {
        static byte[] lockkey = { };//libtolua.so
        static byte[] unlockkey = { };//libtolua.so
        static bool Sk;
        static void Main(string[] args)
        {
            if (args.Length < 1)
                goto End;
            Console.WriteLine("File : " + Path.GetFileName(args[0]));
            var bytes = File.ReadAllBytes(args[0]);
            if (bytes[3] == 0x02)
                Sk = true;
            else
                Sk = false;
            Console.WriteLine("Size : " + new FileInfo(args[0]).Length);
            var reader = new BinaryReader(new MemoryStream(bytes));
            //_read_header
            var magic = reader.ReadBytes(3);
            Console.WriteLine("Magic : " + BitConverter.ToString(magic));
            var version = reader.ReadByte();
            Console.WriteLine("Version : " + version);
            var bits = reader.ReadUleb128();
            Console.WriteLine("Bits : " + bits);
            var is_stripped = ((bits & 2u) != 0u);
            if (!is_stripped)
            {
                var length = reader.ReadUleb128();
                var name = Encoding.UTF8.GetString(reader.ReadBytes((int)length));
            }
            //_read_prototypes
            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                var size = reader.ReadUleb128();
                if (size == 0)
                    break;
                var next = reader.BaseStream.Position + size;
                bits = reader.ReadByte();//_read_flags
                var arguments_count = reader.ReadByte();//_read_counts_and_sizes
                var framesize = reader.ReadByte();
                var upvalues_count = reader.ReadByte();
                var complex_constants_count = reader.ReadUleb128();
                var numeric_constants_count = reader.ReadUleb128();
                var instructions_count = reader.ReadUleb128();
                var start = (int)reader.BaseStream.Position;
                if (Sk)
                {
                    //Encrypt
                    bytes[3] = 0x80;
                    bytes = lj_bclock(start, bytes, (int)instructions_count);
                    Console.WriteLine("--==Encrypt==--");
                }
                else
                {
                    //Decrypt
                    bytes[3] = 2;
                    bytes = lj_bcunlock(start, bytes, (int)instructions_count);
                    Console.WriteLine("--==Decrypt==--");
                }
                //
                reader.BaseStream.Position = next;
            }
            File.WriteAllBytes(args[0], bytes);
            End:
            Console.WriteLine("Press one key to end");
            Console.ReadKey();
        }

        static byte[] lj_bclock(int start, byte[] bytes, int count)
        {
            var result = start;
            result += 4;
            var v2 = 0;
            do
            {
                var v3 = bytes[result - 4];
                result += 4;
                var v4 = bytes[result - 7] ^ v2++;
                bytes[result - 8] = (byte)(lockkey[v3] ^ v4);
            }
            while (v2 != count);
            return bytes;
        }

        static byte[] lj_bcunlock(int start, byte[] bytes, int count)
        {
            var result = start;
            result += 4;
            var v2 = 0;
            do
            {
                var v3 = bytes[result - 4];
                result += 4;
                var v4 = bytes[result - 7] ^ v3 ^ (v2++ & 0xFF);
                bytes[result - 8] = unlockkey[v4];
            }
            while (v2 != count);
            return bytes;
        }

        static public uint ReadUleb128(this BinaryReader reader)
        {
            uint value = reader.ReadByte();
            if (value >= 0x80)
            {
                var bitshift = 0;
                value &= 0x7f;
                while (true)
                {
                    var b = reader.ReadByte();
                    bitshift += 7;
                    value |= (uint)((b & 0x7f) << bitshift);
                    if (b < 0x80)
                        break;
                }
            }
            return value;
        }
    }
}
