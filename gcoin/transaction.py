#!/usr/bin/python

import copy
from _functools import reduce

from gcoin.main import *



### Hex to bin converter and vice versa for objects


def json_is_base(obj, base):
    if not is_python2 and isinstance(obj, bytes):
        return False

    alpha = get_code_string(base)
    if isinstance(obj, string_types):
        for i in range(len(obj)):
            if alpha.find(obj[i]) == -1:
                return False
        return True
    elif isinstance(obj, int_types) or obj is None:
        return True
    elif isinstance(obj, list):
        for i in range(len(obj)):
            if not json_is_base(obj[i], base):
                return False
        return True
    else:
        for x in obj:
            if not json_is_base(obj[x], base):
                return False
        return True


def json_changebase(obj, changer):
    if isinstance(obj, string_or_bytes_types):
        return changer(obj)
    elif isinstance(obj, int_types) or obj is None:
        return obj
    elif isinstance(obj, list):
        return [json_changebase(x, changer) for x in obj]
    return dict((x, json_changebase(obj[x], changer)) for x in obj)


# Transaction serialization and deserialization


def deserialize(tx):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        # tx = bytes(bytearray.fromhex(tx))
        return json_changebase(deserialize(binascii.unhexlify(tx)),
                               lambda x: safe_hexlify(x))
    # http://stackoverflow.com/questions/4851463/python-closure-write-to-variable-in-parent-scope
    # Python's scoping rules are demented, requiring me to make pos an object
    # so that it is call-by-reference
    pos = [0]

    def read_as_int(bytez):
        pos[0] += bytez
        return decode(tx[pos[0] - bytez:pos[0]][::-1], 256)

    def read_var_int():
        pos[0] += 1

        val = from_byte_to_int(tx[pos[0] - 1])
        if val < 253:
            return val
        return read_as_int(pow(2, val - 252))

    def read_bytes(bytez):
        pos[0] += bytez
        return tx[pos[0] - bytez:pos[0]]

    def read_var_string():
        size = read_var_int()
        return read_bytes(size)

    obj = {"ins": [], "outs": []}
    obj["version"] = read_as_int(4)
    ins = read_var_int()
    for i in range(ins):
        obj["ins"].append({
            "outpoint": {
                "hash": read_bytes(32)[::-1],
                "index": read_as_int(4)
            },
            "script": read_var_string(),
            "sequence": read_as_int(4)
        })
    outs = read_var_int()
    for i in range(outs):
        obj["outs"].append({
            "value": read_as_int(8),
            "script": read_var_string(),
            "color": read_as_int(4)
        })
    obj["locktime"] = read_as_int(4)
    obj["type"] = read_as_int(4)
    return obj


def serialize(txobj):
    # if isinstance(txobj, bytes):
    #    txobj = bytes_to_hex_string(txobj)
    o = []
    if json_is_base(txobj, 16):
        json_changedbase = json_changebase(txobj, lambda x: binascii.unhexlify(x))
        hexlified = safe_hexlify(serialize(json_changedbase))
        return hexlified
    o.append(encode(txobj["version"], 256, 4)[::-1])
    o.append(num_to_var_int(len(txobj["ins"])))
    for inp in txobj["ins"]:
        o.append(inp["outpoint"]["hash"][::-1])
        o.append(encode(inp["outpoint"]["index"], 256, 4)[::-1])
        o.append(num_to_var_int(len(inp["script"])) + (inp["script"] if inp["script"] or is_python2 else bytes()))
        o.append(encode(inp["sequence"], 256, 4)[::-1])
    o.append(num_to_var_int(len(txobj["outs"])))
    for out in txobj["outs"]:
        o.append(encode(out["value"], 256, 8)[::-1])
        o.append(num_to_var_int(len(out["script"])) + out["script"])
        o.append(encode(out["color"], 256, 4)[::-1])
    o.append(encode(txobj["locktime"], 256, 4)[::-1])
    o.append(encode(txobj["type"], 256, 4)[::-1])

    return ''.join(o) if is_python2 else reduce(lambda x, y: x + y, o, bytes())


# Hashing transactions for signing

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
# this works like SIGHASH_ANYONECANPAY | SIGHASH_ALL, might as well make it explicit while
# we fix the constant
SIGHASH_ANYONECANPAY = 0x81


def signature_form(tx, i, hashcode=SIGHASH_ALL):
    i, hashcode = int(i), int(hashcode)
    if isinstance(tx, string_or_bytes_types):
        return serialize(signature_form(deserialize(tx), i, hashcode))
    newtx = copy.deepcopy(tx)
    for index, inp in enumerate(newtx["ins"]):
        if index != i:
            inp["script"] = ""
    if hashcode == SIGHASH_NONE:
        newtx["outs"] = []
    elif hashcode == SIGHASH_SINGLE:
        newtx["outs"] = newtx["outs"][:len(newtx["ins"])]
        for out in newtx["outs"][:len(newtx["ins"]) - 1]:
            out['value'] = 2 ** 64 - 1
            out['script'] = ""
    elif hashcode == SIGHASH_ANYONECANPAY:
        newtx["ins"] = [newtx["ins"][i]]
    else:
        pass
    return newtx


# Making the actual signatures


def der_encode_sig(v, r, s):
    b1, b2 = safe_hexlify(encode(r, 256)), safe_hexlify(encode(s, 256))
    if len(b1) and b1[0] in '89abcdef':
        b1 = '00' + b1
    if len(b2) and b2[0] in '89abcdef':
        b2 = '00' + b2
    left = '02' + encode(len(b1) // 2, 16, 2) + b1
    right = '02' + encode(len(b2) // 2, 16, 2) + b2
    return '30' + encode(len(left + right) // 2, 16, 2) + left + right


def der_decode_sig(sig):
    leftlen = decode(sig[6:8], 16) * 2
    left = sig[8:8 + leftlen]
    rightlen = decode(sig[10 + leftlen:12 + leftlen], 16) * 2
    right = sig[12 + leftlen:12 + leftlen + rightlen]
    return (None, decode(left, 16), decode(right, 16))


def is_bip66(sig):
    """Checks hex DER sig for BIP66 consistency"""
    # https://raw.githubusercontent.com/bitcoin/bips/master/bip-0066.mediawiki
    # 0x30  [total-len]  0x02  [R-len]  [R]  0x02  [S-len]  [S]  [sighash]
    sig = bytearray.fromhex(sig) if re.match('^[0-9a-fA-F]*$', sig) else bytearray(sig)
    if (sig[0] == 0x30) and (sig[1] == len(sig) - 2):  # check if sighash is missing
        sig.extend(b"\1")  # add SIGHASH_ALL for testing
    # assert (sig[-1] & 124 == 0) and (not not sig[-1]), "Bad SIGHASH value"

    if len(sig) < 9 or len(sig) > 73: return False
    if (sig[0] != 0x30): return False
    if (sig[1] != len(sig) - 3): return False
    rlen = sig[3]
    if (5 + rlen >= len(sig)): return False
    slen = sig[5 + rlen]
    if (rlen + slen + 7 != len(sig)): return False
    if (sig[2] != 0x02): return False
    if (rlen == 0): return False
    if (sig[4] & 0x80): return False
    if (rlen > 1 and (sig[4] == 0x00) and not (sig[5] & 0x80)): return False
    if (sig[4 + rlen] != 0x02): return False
    if (slen == 0): return False
    if (sig[rlen + 6] & 0x80): return False
    if (slen > 1 and (sig[6 + rlen] == 0x00) and not (sig[7 + rlen] & 0x80)):
        return False
    return True


def txhash(tx, hashcode=None):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        tx = changebase(tx, 16, 256)
    if hashcode:
        return dbl_sha256(from_string_to_bytes(tx) + encode(int(hashcode), 256, 4)[::-1])
    else:
        return safe_hexlify(bin_dbl_sha256(tx)[::-1])


def bin_txhash(tx, hashcode=None):
    return binascii.unhexlify(txhash(tx, hashcode))


def ecdsa_tx_sign(tx, priv, hashcode=SIGHASH_ALL):
    rawsig = ecdsa_raw_sign(bin_txhash(tx, hashcode), priv)
    return der_encode_sig(*rawsig) + encode(hashcode, 16, 2)


def ecdsa_tx_verify(tx, sig, pub, hashcode=SIGHASH_ALL):
    return ecdsa_raw_verify(bin_txhash(tx, hashcode), der_decode_sig(sig), pub)


def ecdsa_tx_recover(tx, sig, hashcode=SIGHASH_ALL):
    z = bin_txhash(tx, hashcode)
    _, r, s = der_decode_sig(sig)
    left = ecdsa_raw_recover(z, (0, r, s))
    right = ecdsa_raw_recover(z, (1, r, s))
    return (encode_pubkey(left, 'hex'), encode_pubkey(right, 'hex'))


# Scripts


def mk_pubkey_script(addr):
    # Keep the auxiliary functions around for altcoins' sake
    return '76a914' + b58check_to_hex(addr) + '88ac'


def mk_scripthash_script(addr):
    return 'a914' + b58check_to_hex(addr) + '87'


# Address representation to output script


def address_to_script(addr):
    if addr[0] == '3' or addr[0] == '2':
        return mk_scripthash_script(addr)
    else:
        return mk_pubkey_script(addr)


# Output script to address representation


def script_to_address(script, vbyte=0):
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac' and len(script) == 25:
        return bin_to_b58check(script[3:-2], vbyte)  # pubkey hash addresses
    else:
        if vbyte in [111, 196]:
            # Testnet
            scripthash_byte = 196
        elif vbyte == 0:
            # Mainnet
            scripthash_byte = 5
        else:
            scripthash_byte = vbyte
        # BIP0016 scripthash addresses
        return bin_to_b58check(script[2:-1], scripthash_byte)


def p2sh_scriptaddr(script, magicbyte=5):
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    return hex_to_b58check(hash160(script), magicbyte)


scriptaddr = p2sh_scriptaddr


def deserialize_script(script):
    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
        return json_changebase(deserialize_script(binascii.unhexlify(script)),
                               lambda x: safe_hexlify(x))
    out, pos = [], 0
    while pos < len(script):
        code = from_byte_to_int(script[pos])
        if code == 0:
            out.append(None)
            pos += 1
        elif code <= 75:
            out.append(script[pos + 1:pos + 1 + code])
            pos += 1 + code
        elif code <= 78:
            szsz = pow(2, code - 76)
            sz = decode(script[pos + szsz: pos:-1], 256)
            out.append(script[pos + 1 + szsz:pos + 1 + szsz + sz])
            pos += 1 + szsz + sz
        elif code <= 96:
            out.append(code - 80)
            pos += 1
        else:
            out.append(code)
            pos += 1
    return out


def serialize_script_unit(unit):
    if isinstance(unit, int):
        if unit < 16:
            return from_int_to_byte(unit + 80)
        else:
            return from_int_to_byte(unit)
    elif unit is None:
        return b'\x00'
    else:
        if len(unit) <= 75:
            return from_int_to_byte(len(unit)) + unit
        elif len(unit) < 256:
            return from_int_to_byte(76) + from_int_to_byte(len(unit)) + unit
        elif len(unit) < 65536:
            return from_int_to_byte(77) + encode(len(unit), 256, 2)[::-1] + unit
        else:
            return from_int_to_byte(78) + encode(len(unit), 256, 4)[::-1] + unit


if is_python2:
    def serialize_script(script):
        if json_is_base(script, 16):
            return binascii.hexlify(serialize_script(
                json_changebase(script, lambda x: binascii.unhexlify(x))))
        return ''.join(map(serialize_script_unit, script))
else:
    def serialize_script(script):
        if json_is_base(script, 16):
            return safe_hexlify(serialize_script(
                json_changebase(script, lambda x: binascii.unhexlify(x))))

        result = bytes()
        for b in map(serialize_script_unit, script):
            result += b if isinstance(b, bytes) else bytes(b, 'utf-8')
        return result


def mk_multisig_script(*args):  # [pubs],k or pub1,pub2...pub[n],k
    if isinstance(args[0], list):
        pubs, k = args[0], int(args[1])
    else:
        pubs = list(filter(lambda x: len(str(x)) >= 32, args))
        k = int(args[len(pubs)])
    return serialize_script([k] + pubs + [len(pubs)] + [0xae])


# Signing


def sign(tx, i, priv, hashcode=SIGHASH_ALL):
    i = int(i)
    if (not is_python2 and isinstance(re, bytes)) or not re.match('^[0-9a-fA-F]*$', tx):
        return binascii.unhexlify(sign(safe_hexlify(tx), i, priv))
    if len(priv) <= 33:
        priv = safe_hexlify(priv)
    pub = privkey_to_pubkey(priv)
    address = pubkey_to_address(pub)
    signing_tx = signature_form(tx, i, hashcode)
    sig = ecdsa_tx_sign(signing_tx, priv, hashcode)
    txobj = deserialize(tx)
    # Obsolete pay-to-pubkey transaction.
    # https://en.bitcoin.it/wiki/Script#Obsolete_pay-to-pubkey_transaction
    if re.match('^21[0-9a-fA-F]{66}ac', txobj['ins'][i]['script']):
        txobj["ins"][i]["script"] = serialize_script([sig])
    else:
        txobj["ins"][i]["script"] = serialize_script([sig, pub])
    return serialize(txobj)


def signall(tx, priv):
    for i in range(len(deserialize(tx)["ins"])):
        tx = sign(tx, i, priv)
    return tx


def multisign(tx, i, script, priv, hashcode=SIGHASH_ALL):
    """Create a signed signature of multisig transaction.

    :param tx: A transaction to be signed.
    :param i: The index of input to sign.
    :param script: The redemption script.
    :param priv: Private key used to sign.
    :param hashcode: Hashcode type.

    :return: A signature.
    """
    if re.match('^[0-9a-fA-F]*$', tx):
        tx = binascii.unhexlify(tx)
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = script
    tx = serialize(txobj)
    modtx = signature_form(tx, i, hashcode)
    return ecdsa_tx_sign(modtx, priv, hashcode)


def apply_multisignatures(tx, i, script, sigs):
    """Create a signed transaction with signatures derived before and the redemption script.

    :param tx: A transaction to be signed.
    :param i: The index of input to sign.
    :param script: The redemption script.
    :param sigs: A list of signatures derived before.

    :return: A Signed transaction.
    """
    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    sigs = [binascii.unhexlify(x) if x[:2] == '30' else x for x in sigs]
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        return safe_hexlify(apply_multisignatures(binascii.unhexlify(tx), i, script, sigs))

    # Not pushing empty elements on the top of the stack if passing no
    # script (in case of bare multisig inputs there is no script)
    script_blob = [] if script.__len__() == 0 else [script]

    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = serialize_script([None] + sigs + script_blob)
    return serialize(txobj)


def signall_multisig(tx, script, privs):
    """Sign a multisig transaction.

    :params tx: A serialized transaction.
    :params script: A redemption script.
    :params privs: A list of private key.

    :return: Signed transaction.
    """
    # see OP_2-OP_16 in https://en.bitcoin.it/wiki/Script#Constants
    sigsrequired = int(script[:2], 16) - 80
    for i in range(len(deserialize(tx)["ins"])):
        sigs = []
        for priv in privs:
            sigs.append(multisign(tx, i, script, priv))
        tx = apply_multisignatures(tx, i, script, sigs[:sigsrequired])
    return tx


def is_inp(arg):
    return len(arg) > 64 or "output" in arg or "outpoint" in arg


def make_raw_tx(ins, outs):
    """Make raw transaction from inputs and outputs.

    :param ins: A list of input. The format of input is given below.

    input: {
        'tx_id': '',
        'index': 0,
        'script': ''
    }

    :param outs: A list of output. The format of output is given below.

    output: {
        'address': '',
        'value': 0,
        'color': 0
    }

    :return: Serialized raw transaction.
    """
    tx_obj = {'locktime': 0, 'version': 1, 'ins': [], 'outs': [], 'type': 0}
    for i in ins:
        tx_obj['ins'].append({
            'outpoint': {
                'hash': i['tx_id'],
                'index': i['index']
            },
            'script': i['script'],
            'sequence': 0xffffffff
        })
    for o in outs:
        out_obj = {'script': address_to_script(o['address']),
                   'value': o['value'],
                   'color': o['color']}
        tx_obj['outs'].append(out_obj)
    return serialize(tx_obj)


def make_mint_raw_tx(address, color, value):
    """Make raw transaction for minting asset.

    :param address: The address to mint.
    :param color: The color to mint.
    :param value: The value to mint (in satoshi).
    :return: Serialized raw transaction.
    """
    tx_obj = {'locktime': 0, 'version': 1, 'ins': [], 'outs': [], 'type': 1}
    tx_obj['ins'].append({
        'outpoint': {
            'hash': '0' * 64,
            'index': 0xffffffff
        },
        'script': address_to_script(address),
        'sequence': 0xffffffff
    })
    tx_obj['outs'].append({'script': address_to_script(address),
                           'value': value,
                           'color': color})
    return serialize(tx_obj)


def select(unspent, value):
    value = int(value)
    high = [u for u in unspent if u["value"] >= value]
    high.sort(key=lambda u: u["value"])
    low = [u for u in unspent if u["value"] < value]
    low.sort(key=lambda u: -u["value"])
    if len(high):
        return [high[0]]
    i, tv = 0, 0
    while tv < value and i < len(low):
        tv += low[i]["value"]
        i += 1
    if tv < value:
        raise Exception("Not enough funds")
    return low[:i]
