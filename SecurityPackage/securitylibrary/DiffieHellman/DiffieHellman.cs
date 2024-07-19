using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int pow(int a, int b, int c)
        {
            int result = 1;
            for (int i = 0; i < b; i++)
            {
                result = (result * a) % c;
            }
            return result;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int ya = pow(alpha, xa, q);
            int yb = pow(alpha, xb, q);

            int k1 = pow(yb, xa, q);
            int k2 = pow(ya, xb, q);

            List<int> result = new List<int>
            {
                k1,
                k2
            };

            return result;
        }
    }
}