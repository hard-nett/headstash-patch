

# install secret-cli

if ! command -v scrt &> /dev/null
then
    echo "The Secret Network CLI is not installed, downloading & installing."
    wget https://github.com/scrtlabs/SecretNetwork/releases/download/v1.12.2/secretcli-Linux > /root/go/bin/scrt
    sudo chmod +x /root/go/bin/scrt
else
    # Command exists
    echo "The Secret Network CLI is installed."
fi

# define code-id or fetch cw-20 raw wasm file
CODE_ID=123
CW20_GIT=https://github.com/scrtlabs/snip20-reference-impl
# store or instantiate
TYPE =-i 

if ! command -v docker &> /dev/null
then
    echo "Docker is not installed, downloading & installing."
    snap install docker
else
    # Command exists
    echo "Docker is now installed."
fi


git clone $CW20_GIT snip20
cd snip20

docker run --rm -v "$(pwd)":/contract   --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target   --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry   enigmampc/secret-contract-optimizer
mv contract.wasm.gz ../ && cd ../


## instantiate or store and instantitate contracts
# Check if the number of arguments is less than 2 (excluding the script name)
if [ "$#" -lt 2 ]; then
  echo "Usage: $0 [-s|-i] name symbol [supported_denoms]"
  exit 1
fi

# Extract the action type (instantiate or upload) and values
action=$1
name=$2
symbol=$3
supported_denoms=$4

# Run the Node.js script with the chosen action and values
if [ "$action" == "-i" ]; then
  node your_script.js "$action" "$name" "$symbol" "$supported_denoms"
elif [ "$action" == "-s" ]; then
  node your_script.js "$action"
else
  echo "Invalid action type. Please provide -s or -i."
fi
