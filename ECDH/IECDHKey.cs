using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptonite.ECDH
{
    public interface IECDHKey
    {
        public byte[] GetBytes();
    }
}
