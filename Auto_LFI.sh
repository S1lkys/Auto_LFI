read -p $'\e[1;92m Target URL: \e[0m' url 
read -p $'\e[1;92m List of directories: \e[0m' wl_pass
read -p $'\e[1;92m Parameter to test: \e[0m' parameter 

wl_pass="${wl_pass}"
url="${url}"
parameter="${parameter}"

count_pass=$(wc -l $wl_pass | cut -d " " -f1)

for fn in `cat $wl_pass`; do
curl -X POST -k $url -d $parameter"="$fn >> result
done

echo "Fertig, siehe in result nach"
