// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.AspNetCore.Antiforgery
{
    public class AntiforgerySerializationContext : IDisposable
    {
        // Avoid allocating 256 bytes (the default) and using 18 (the AntiforgeryToken minimum). 64 bytes is enough for
        // a short username or claim UID and some additional data. MemoryStream bumps capacity to 256 if exceeded.
        private const int InitialStreamSize = 64;

        // Don't let the MemoryStream grow beyond 1 MB.
        private const int MaximumStreamSize = 0x100000;

        private MemoryStream _memory;
        private BinaryReader _reader;
        private BinaryWriter _writer;
        private SHA256 _sha256;

        public MemoryStream Memory
        {
            get
            {
                if (_memory == null)
                {
                    _memory = new MemoryStream(InitialStreamSize);
                }

                return _memory;
            }
            private set
            {
                _memory = value;
            }
        }

        public BinaryReader Reader
        {
            get
            {
                if (_reader == null)
                {
                    // Leave open to clean up correctly even if only one of the reader or writer has been created.
                    _reader = new BinaryReader(Memory, Encoding.UTF8, leaveOpen: true);
                }

                return _reader;
            }
            private set
            {
                _reader = value;
            }
        }

        public BinaryWriter Writer
        {
            get
            {
                if (_writer == null)
                {
                    // Leave open to clean up correctly even if only one of the reader or writer has been created.
                    _writer = new BinaryWriter(Memory, Encoding.UTF8, leaveOpen: true);
                }

                return _writer;
            }
            private set
            {
                _writer = value;
            }
        }

        public SHA256 Sha256
        {
            get
            {
                if (_sha256 == null)
                {
                    _sha256 = SHA256.Create();
                }

                return _sha256;
            }
            private set
            {
                _sha256 = value;
            }
        }

        public void Dispose()
        {
            using (Reader)
            {
                Reader = null;
            }

            using (Writer)
            {
                Writer = null;
            }

            using (Memory)
            {
                Memory = null;
            }

            using (Sha256)
            {
                Sha256 = null;
            }
        }

        public void Reset()
        {
            if (Memory.Capacity > MaximumStreamSize)
            {
                Memory = null;
                Reader = null;
                Writer = null;
            }
            else
            {
                Memory.Position = 0L;
                Memory.SetLength(0L);
            }
        }
    }
}
