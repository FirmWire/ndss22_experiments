

mkdir -p extracted


cd extracted
for img in ../*.zip; do
    cp=`unzip -l $img | grep CP | awk '{print $NF}'`
    unzip -o $img $cp
done
