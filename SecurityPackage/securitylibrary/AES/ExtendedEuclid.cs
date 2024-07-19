using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            // throw new NotImplementedException();
            int A1 = 1, A2 = 0, A3 = baseN, B1 = 0, B2 = 1, B3 = number, q, tmpA1, tmpA2, tmpA3;
            while (B3 > 1)
            {
                q = A3 / B3;
                tmpA1 = A1;
                tmpA2 = A2;
                tmpA3 = A3;
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = tmpA1 - (q * B1);
                B2 = tmpA2 - (q * B2);
                B3 = tmpA3 - (q * B3);
            }

            return (B3 == 0)? -1 : ( (B2 % baseN + baseN) % baseN ); 
        }
    }
}
