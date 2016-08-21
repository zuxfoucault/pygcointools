### Credit: http://2bhackathon.org/
# Pygcointools
###Python library for Gcoin signatures and transactions

### Usage:

#### Import

```
from gcoin import *
```

#### Generate private key

```
priv = sha256('some big long brainwallet password')
```

#### Get public key from private key

```
pub = privtopub(priv)
```

#### Get address from public key

```
addr = pubtoaddr(pub)
```

#### Sign raw transaction

To sign a raw transaction, call `signall` to get the signed transaction. The first parameter is the raw transaction and the second parameter is the private key.

```
tx = signall(tx, priv)
```

#### Generate multisig address

To generate an m of n multisig address, call `mk_multisig_script` to get the redemption script first. Then pass the redemption script to `scriptaddr` to get the multisignature address.

The first parameter of `mk_multisig_script` is a list of public keys and the second parameter is the number of signatures required.

```
script = mk_multisig_script([pub1, pub2, ..., pubn], m)
maddr = scriptaddr(script)
```

#### Sign raw multisig transaction

Signing a multisig transaction just simply calls `signall_multisig`. The first parameter of `signall_multisig` is the original raw transaction. The second parameter is the redemption script derived from `mk_multisig_script`. The last parameter is a list of private keys that you want to sign.

```
tx = signall_multisig(tx, script, [priv1, priv2, ..., privn])
```

### Listing of main commands:

* privtopub            : (privkey) -> pubkey
* pubtoaddr            : (pubkey) -> address
* privtoaddr           : (privkey) -> address

* random_key           : () -> privkey
* random_electrum_seed : () -> electrum seed

* sign                 : (tx, i, privkey) -> tx with index i signed with privkey
* signall              : (tx, priv) -> signed_tx
* multisign            : (tx, i, script, privkey) -> signature
* apply_multisignatures: (tx, i, script, sigs) -> tx with index i signed with sigs
* signall_multisig     : (tx, script, privkeys) -> signed tx
* scriptaddr           : (script) -> P2SH address
* mk_multisig_script   : (pubkeys, k) -> k-of-n multisig script from pubkeys
