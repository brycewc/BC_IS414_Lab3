using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using EllipticCurve;

namespace BC_IS414_Lab3
{
    class Program
    {
        static void Main(string[] args)
        {
            PrivateKey key1 = new PrivateKey();
            PublicKey wallet1 = key1.publicKey();

            PrivateKey key2 = new PrivateKey();
            PublicKey wallet2 = key2.publicKey();

            Blockchain rootcoin = new Blockchain(2, 100);

            Console.WriteLine("Starting miner up");
            rootcoin.MinePendingTransactions(wallet1);
            Console.WriteLine("\nBalance of wallet1 is $" + rootcoin.GetBalanceOfWallet(wallet1).ToString());

            Transaction tx1 = new Transaction(wallet1, wallet2, 10);
            tx1.SignTransaction(key1);
            rootcoin.AddPendingTransaction(tx1);

            Console.WriteLine("Starting miner up");
            rootcoin.MinePendingTransactions(wallet2);

            Console.WriteLine("\nBalance of wallet1 is $" + rootcoin.GetBalanceOfWallet(wallet1).ToString());
            Console.WriteLine("\nBalance of wallet2 is $" + rootcoin.GetBalanceOfWallet(wallet2).ToString());

            string blockJSON = JsonConvert.SerializeObject(rootcoin, Formatting.Indented);
            Console.WriteLine(blockJSON);

            if(rootcoin.IsChainValid())
            {
                Console.WriteLine("Blockchain is valid");
            }
            else
            {
                Console.WriteLine("Blockchain is invalid");
            }
        }
    }
}
