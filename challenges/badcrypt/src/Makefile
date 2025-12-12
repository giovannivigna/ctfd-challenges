CRYPTKEY=mrrobotrocks # The key must be smaller than filename
FILENAME=plaintext.txt

default: ${FILENAME}.gz.enc
	cp ${FILENAME}.gz.enc ../ro/${FILENAME}.gz.enc

${FILENAME}.gz.enc: badcrypt ${FILENAME}.gz	
	cat ${FILENAME}.gz | ./badcrypt encrypt ${CRYPTKEY} > ${FILENAME}.gz.enc
	cat ${FILENAME}.gz.enc | ./badcrypt decrypt ${CRYPTKEY} > ${FILENAME}_test.gz
	gunzip -f -k ${FILENAME}_test.gz

${FILENAME}.gz: ${FILENAME}
	gzip -f -k ${FILENAME} 

${FILENAME}:
	echo "Why do people insist on inventing their own crypto algorithms?\nThe flag is:" > ${FILENAME}
	cat ../flag/flag >> ${FILENAME}

badcrypt:
	gcc -g -Wall -o badcrypt badcrypt.c

clean:
	rm -f ${FILENAME}
	rm -f badcrypt
	rm -f ${FILENAME}.gz
	rm -f ${FILENAME}.gz.enc
	rm -f ${FILENAME}_test
	rm -f ${FILENAME}_test.gz
