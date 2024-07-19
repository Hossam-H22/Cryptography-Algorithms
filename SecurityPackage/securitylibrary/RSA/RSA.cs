using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int fastPower(int b, int p, int MOD)
        {
            if (p == 0) return 1;
            if (p == 1) return b;

            long ret = fastPower(b, p/2, MOD);

            ret = ret%MOD;
            ret = (ret * ret) % MOD;

            if (p % 2 == 1) ret = (ret * b) % MOD;

            return (int)ret;
        }

        public int modInverse(int e, int MOD)
        {
            for(int i=1; i < MOD; i++)
            {
                int curVal = i * e;

                if (curVal % MOD == 1)
                    return i;
            }

            return -1;
        }

        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            
            return fastPower(M%n, e, n);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phi = (p-1) * (q-1);

            int d = modInverse(e, phi);

            return fastPower(C, d, n);
        }
    }
}
