for PHOTO in *.png
do
  convert ./"$PHOTO" -trim ./"$PHOTO"
done


for PHOTO in *.jpg
do
  convert ./"$PHOTO" -trim ./"$PHOTO"
done
