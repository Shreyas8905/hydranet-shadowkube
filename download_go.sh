source ~/.bashrc
sudo rm -rf /usr/local/go
curl -sL https://go.dev/dl/go1.22.5.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
export PATH=$PATH:/usr/local/go/bin