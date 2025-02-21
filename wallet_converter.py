import base58
import hashlib

#### NETWORK ID'S ####
net_ids = [
    ("KelVPN", 0x1807202300000000)  # Add more, if you want...
]

#### WALLET ADDRESSES ####
wallet_addresses = [
    "Rj7J7MiX2bWy8sNyXy4ynu9Z2SLEiExmG7XFxkWArqbJ2asf23RFfrQNC16VC5AfNAE8oGyVxAXPUJNLRx9H1y1TvWnzGmNZCGBLXCya",
    "Rj7J7MiX2bWy8sNyXy4ynu9Z2SLEiExmG7XFxkWArqbJ2asf23RFfrQNC16VC5AfNAE8oGyVxAXPUJNLRx9H1y1TvWnzGmNZCGBLXCa"
]

def parse_cf_address(address):
    bdata = base58.b58decode(address)
    version = bdata[0]
    net_id = int.from_bytes(bdata[1:9], byteorder="little")
    sign_id = int.from_bytes(bdata[9:13], byteorder="little")
    public_hash = bdata[13:45]
    control_hash = bdata[45:]

    hash = hashlib.sha3_256()
    hash.update(bdata[:45])
    summary_hash = hash.digest()

    if summary_hash != control_hash:
        print(f"Invalid address: {address}")
        raise ValueError

    return version, net_id, sign_id, public_hash, summary_hash, control_hash

def build_cf_address(version, net_id, sign_id, public_hash):
    net_id_bytes = net_id.to_bytes(8, byteorder="little")
    sign_id_bytes = sign_id.to_bytes(4, byteorder="little")

    raw_address = (
        version.to_bytes(1, "big")
        + net_id_bytes
        + sign_id_bytes
        + public_hash
    )

    hash = hashlib.sha3_256()
    hash.update(raw_address)
    control_hash = hash.digest()
    full_address = raw_address + control_hash
    return base58.b58encode(full_address).decode()

def convert_address(address):
    version, net_id, sign_id, public_hash, _, _ = parse_cf_address(address)

    for name, new_net_id in net_ids:
        converted_address = build_cf_address(version, new_net_id, sign_id, public_hash)
        print(f"Converted address for {name}: {converted_address}")

for address in wallet_addresses:
    convert_address(address)
