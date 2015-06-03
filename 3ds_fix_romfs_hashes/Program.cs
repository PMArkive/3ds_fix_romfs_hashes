using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace _3ds_fix_romfs_hashes
{
    class Program
    {
        class IVFC_LevelHeader
        {
            public UInt64 LogicalOffset;
            public UInt64 HashDataSize;
            public UInt32 BlockSize;
            public UInt32 Reserved;

            private string className = "IVFC_LevelHeader";
            private int level;

            public IVFC_LevelHeader(int level)
            {
                this.level = level;
            }

            public override string ToString()
            {
                return String.Format("{4} #{5}: LogicalOffset[{0:x16}] HashDataSize[{1:x16}] BlockSize[{2:x8}] Reserved[{3:x8}]", LogicalOffset, HashDataSize, BlockSize, Reserved, className, level);
            }
        }

        class IVFC_Level
        {
            public UInt64 DataOffset;
            public UInt64 DataSize;
            public UInt64 HashOffset;
            public UInt32 HashBlockSize;

            public List<byte[]> HashBytes = new List<byte[]>();

            private string className = "IVFC_Level";
            private int level;

            public IVFC_Level(int level)
            {
                this.level = level;
            }

            public override string ToString()
            {
                return String.Format("{4} #{5}: DataOffset[{0:x16}] DataSize[{1:x16}] HashOffset[{2:x16}] HashBlockSize[{3:x8}]", DataOffset, DataSize, HashOffset, HashBlockSize, className, level);
            }
        }

        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("usage: {0} romfs.bin", AppDomain.CurrentDomain.FriendlyName);
                Environment.Exit(-1);
            }

            string romfs = args[0];

            using (FileStream stream = new FileStream(romfs, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            using (BinaryReader reader = new BinaryReader(stream))
            {
                UInt64 bodyOffset = 0;
                UInt64 bodySize = 0;

                List<IVFC_LevelHeader> IVFC_LevelHeaders = new List<IVFC_LevelHeader>();
                IVFC_LevelHeaders.Add(new IVFC_LevelHeader(0)); // Level 0
                IVFC_LevelHeaders.Add(new IVFC_LevelHeader(1)); // Level 1
                IVFC_LevelHeaders.Add(new IVFC_LevelHeader(2)); // Level 2

                List<IVFC_Level> IVFC_Levels = new List<IVFC_Level>();
                IVFC_Levels.Add(new IVFC_Level(0)); // Level 0
                IVFC_Levels.Add(new IVFC_Level(1)); // Level 1
                IVFC_Levels.Add(new IVFC_Level(2)); // Level 2

                uint masterHashSize = 0;
                if (reader.ReadUInt32() != 0x43465649)
                {
                    Console.WriteLine(
                        "Expected IVFC header, found something else. Not a valid (possibly encrypted?) RomFS file.");
                    Environment.Exit(-1);
                }

                reader.BaseStream.Seek(0x08, SeekOrigin.Begin);
                masterHashSize = reader.ReadUInt32();
                IVFC_Levels[0].HashOffset = 0x60;

                for (int i = 0; i < IVFC_LevelHeaders.Count; i++)
                {
                    reader.BaseStream.Seek(0x0c + (i * 24), SeekOrigin.Begin);
                    IVFC_LevelHeaders[i].LogicalOffset = reader.ReadUInt64();
                    IVFC_LevelHeaders[i].HashDataSize = reader.ReadUInt64();
                    IVFC_LevelHeaders[i].BlockSize = reader.ReadUInt32();
                    IVFC_LevelHeaders[i].Reserved = reader.ReadUInt32();

                    IVFC_Levels[IVFC_Levels.Count - i - 1].HashBlockSize =
                        Convert.ToUInt32(1 << Convert.ToInt32(IVFC_LevelHeaders[i].BlockSize));
                }

                reader.BaseStream.Seek(0x1000, SeekOrigin.Begin);
                int romfsHeaderSize = reader.ReadInt32();
                reader.BaseStream.Seek(0x1000 + romfsHeaderSize - 0x08 - 0x04, SeekOrigin.Begin);

                bodyOffset = Align64(IVFC_Levels[0].HashOffset + masterHashSize, IVFC_Levels[2].HashBlockSize);
                bodySize = IVFC_LevelHeaders[2].HashDataSize;

                IVFC_Levels[2].DataOffset = bodyOffset;
                IVFC_Levels[2].DataSize = Align64(bodySize, IVFC_Levels[2].HashBlockSize);

                IVFC_Levels[1].HashOffset = Align64(bodyOffset + bodySize, IVFC_Levels[2].HashBlockSize);
                IVFC_Levels[2].HashOffset = IVFC_Levels[1].HashOffset + IVFC_LevelHeaders[1].LogicalOffset -
                                            IVFC_LevelHeaders[0].LogicalOffset;

                IVFC_Levels[1].DataOffset = IVFC_Levels[2].HashOffset;
                IVFC_Levels[1].DataSize = Align64(IVFC_LevelHeaders[1].HashDataSize, IVFC_Levels[1].HashBlockSize);

                IVFC_Levels[0].DataOffset = IVFC_Levels[1].HashOffset;
                IVFC_Levels[0].DataSize = Align64(IVFC_LevelHeaders[0].HashDataSize, IVFC_Levels[0].HashBlockSize);

                // Generate IVFC hashes
                GenerateIvfcHashBlock(stream, (long)IVFC_Levels[2].DataOffset, (long)IVFC_Levels[2].DataSize, (long)IVFC_Levels[2].HashOffset, (int)IVFC_Levels[2].HashBlockSize, 2); // Level 2
                GenerateIvfcHashBlock(stream, (long)IVFC_Levels[1].DataOffset, (long)IVFC_Levels[1].DataSize, (long)IVFC_Levels[1].HashOffset, (int)IVFC_Levels[1].HashBlockSize, 1); // Level 1
                GenerateIvfcHashBlock(stream, (long)IVFC_Levels[0].DataOffset, (long)IVFC_Levels[0].DataSize, (long)IVFC_Levels[0].HashOffset, (int)IVFC_Levels[0].HashBlockSize, 0); // Level 0


                // Generate superblock hash
                int masterHashRegionSize = (int)Align64(masterHashSize, 0x200);
                byte[] masterHashData = new byte[masterHashRegionSize];
                stream.Seek(0, SeekOrigin.Begin);
                stream.Read(masterHashData, 0, masterHashData.Length);

                SHA256Managed sha = new SHA256Managed();
                byte[] masterHash = sha.ComputeHash(masterHashData);
                Console.WriteLine("Superblock Hash: {0}", BitConverter.ToString(masterHash).Replace("-", " "));
            }
        }

        private static UInt64 Align64(UInt64 offset, UInt32 alignment)
        {
            UInt64 mask = ~(alignment - 1);
            return (offset + (alignment - 1)) & mask;
        }

        static void GenerateIvfcHashBlock(FileStream stream, long dataOffset, long dataSize, long hashOffset, int blockSize, int level)
        {
            SHA256Managed sha = new SHA256Managed();

            Console.WriteLine("Generating level #{0} IVFC hashes...", level);

            stream.Seek(dataOffset, SeekOrigin.Begin);

            int curRead = 0;
            List<byte[]> hashData = new List<byte[]>();
            while (curRead < dataSize)
            {
                byte[] buffer = new byte[blockSize];
                stream.Read(buffer, 0, blockSize);

                byte[] hash = sha.ComputeHash(buffer);
                hashData.Add(hash);

                curRead += blockSize;
            }

            stream.Seek(hashOffset, SeekOrigin.Begin);
            foreach (var data in hashData)
            {
                stream.Write(data, 0, data.Length);
            }
        }
    }
}
