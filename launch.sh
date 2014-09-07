set -euo pipefail
IFS=$'\n\t'

IP=$1
FLAGS=$2

BINARY_NAME=bitnet_server

go build -o $BINARY_NAME github.com/ortutay/bitnet/server

echo "Connecting to $IP to launch $BINARY_NAME with flags $FLAGS"

ssh -i ~/keypair.pem "ubuntu@$IP" "if pgrep $BINARY_NAME &> /dev/null ; then killall $BINARY_NAME ; fi"
scp -i ~/keypair.pem "./$BINARY_NAME" "ubuntu@$IP:/home/ubuntu/$BINARY_NAME"
ssh -i ~/keypair.pem "ubuntu@$IP" "nohup /home/ubuntu/$BINARY_NAME $FLAGS &"
