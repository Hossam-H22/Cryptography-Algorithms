using SecurityLibrary.DiffieHellman;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;




namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        SecurityLibrary.DiffieHellman.DiffieHellman diffieHellman = new SecurityLibrary.DiffieHellman.DiffieHellman();

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            long encryptedPart1 = diffieHellman.pow(alpha, k, q);
            long encryptedPart2 = (m * diffieHellman.pow(y, k, q)) % q;

            return new List<long> { encryptedPart1, encryptedPart2 };
        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            long sharedSecret = diffieHellman.pow(c1, x, q);

            long inverseC1 = GetModularInverse(sharedSecret, q);

            int plainText = (int)((c2 * inverseC1) % q);

            return plainText;
        }

        private long GetModularInverse(long a, long n)
        {
            long i = n, v = 0, d = 1;
            while (a > 0)
            {
                long t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }
    }
}
