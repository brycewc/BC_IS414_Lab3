using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using EllipticCurve;

namespace BC_IS414_Lab3
{
    class Transaction
    {
        public PublicKey FromAddress { get; set; }
        public PublicKey ToAddress { get; set; }
        public decimal Amount { get; set; }
        public Signature Signiture { get; set; }

        public Transaction(PublicKey fromaddress, PublicKey toaddress, decimal amount)
        {
            this.FromAddress = fromaddress;
            this.ToAddress = toaddress;
            this.Amount = amount;
        }

        public void SignTransaction(PrivateKey signingkey)
        {
            string fromaddressDER = BitConverter.ToString(FromAddress.toDer()).Replace("-", "");
            string signingDER = BitConverter.ToString(signingkey.toDer()).Replace("-", "");

            if(fromaddressDER != signingDER)
            {
                throw new Exception("You cannot sign transactions for other wallets");
            }

            string txHash = this.CalculateHash();
            this.Signiture = Ecdsa.sign(txHash, signingkey);
        }

        public string CalculateHash()
        {
            string fromaddressDER = BitConverter.ToString(FromAddress.toDer()).Replace("-", "");
            string toaddressDER = BitConverter.ToString(ToAddress.toDer()).Replace("-", "");
            string transactiondata = fromaddressDER + toaddressDER + Amount;
            byte[] tdBytes = Encoding.ASCII.GetBytes(transactiondata);
            return BitConverter.ToString(SHA256.Create().ComputeHash(tdBytes)).Replace("-", "");
        }

        public bool IsValid()
        {
            if (FromAddress is null) return true;

            if(this.Signiture is null)
            {
                throw new Exception("No signiture in this transaction");
            }

            return Ecdsa.verify(this.CalculateHash(), this.Signiture, this.FromAddress);
        }
    }
}
