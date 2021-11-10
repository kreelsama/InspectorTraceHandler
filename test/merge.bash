cnt=1
declare -i cnt
savefile="${@: -1}"

for file in $@
do
    if [[ $cnt -eq 1 ]]
    then 
        cat $file > $savefile
        echo $cnt
        cnt=$((cnt+1))
    elif [[ $cnt -ne $# ]]
    then
        tail -c +29 $file >> $savefile
        # tail -c +0 $file >> $savefile
        echo $cnt
        cnt=$((cnt+1))
    fi
done