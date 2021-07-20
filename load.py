import argo_client.connection as argo
import cryptol
import os

# docker run --rm -ti \
# -v $PWD/Common:/cryptol/Common \
# -v $PWD/Primitive:/cryptol/Primitive \
# -v $PWD/McEliece_KEM:/cryptol/McEliece_KEM \
# -p 8080:8080 \
# -e CRYPTOLPATH='/cryptol' \
# ghcr.io/galoisinc/cryptol-remote-api:nightly

c = cryptol.connect(url="http://localhost:8080", reset_server=True)

for root, dir, files in os.walk("."):
    for name in files:
        if name.endswith(".cry"):
            new_file = os.path.join(root, name)[2:-4].replace("/", "::")
            print("Loading ", new_file, flush=True)
            c.load_module(new_file).result() # added .result()
            c.reset_server()
