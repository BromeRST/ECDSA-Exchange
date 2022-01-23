const express = require('express');
const app = express();
const cors = require('cors');
const port = 3042;
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const SHA256 = require('crypto-js/sha256');

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

const key1Gen = ec.genKeyPair()
const key2Gen = ec.genKeyPair()
const key3Gen = ec.genKeyPair()
const keys = [
  {
    key: {
      public: key1Gen.getPublic().encode("hex"), 
      private: key1Gen.getPrivate().toString(16)
    }
  },
  {
    key: {
      public: key2Gen.getPublic().encode("hex"), 
      private: key2Gen.getPrivate().toString(16)
    }
  },
  {
    key: {
      public: key3Gen.getPublic().encode("hex"),
      private: key3Gen.getPrivate().toString(16)
    } 
  }
]

const balances = {
  [keys[0].key.public.slice(0, 20)]: 100,
  [keys[1].key.public.slice(0, 20)]: 50,
  [keys[2].key.public.slice(0,20)]: 75,
}

console.log("keys", keys)
console.log(balances)

app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post('/send', (req, res) => {
  const {sender, recipient, amount, privateK} = req.body;

  console.log(privateK)
  console.log(amount)

  let publicKey = ""
  let privateKey = privateK

  if(sender === keys[0].key.public.slice(0, 20)) {
    publicKey = keys[0].key.public
  }
  if(sender === keys[1].key.public.slice(0, 20)) {
    publicKey = keys[1].key.public
  }
  if(sender === keys[2].key.public.slice(0,20)) {
    publicKey = keys[2].key.public
  }

  const key = ec.keyFromPrivate(privateKey)
  const pKey = ec.keyFromPublic(publicKey, "hex")
  const transactionHash = SHA256(balances[sender] + balances[recipient] + amount)
  const signaturePrev = key.sign(transactionHash.toString())
  const signature = {
    r: signaturePrev.r.toString(16),
    s: signaturePrev.s.toString(16)
  }
  console.log(signature)

  console.log(pKey.verify(transactionHash.toString(), signature))
  if (pKey.verify(transactionHash.toString(), signature)) {
    balances[sender] -= amount;
    balances[recipient] = (balances[recipient] || 0) + +amount;
    res.send({ balance: balances[sender] });
  } else {
    console.log("transaction not allowed")
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});
