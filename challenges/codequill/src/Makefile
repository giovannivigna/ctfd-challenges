SERVICE=codequill

all:
	codeql database create ${SERVICE}-db --overwrite --language=cpp --command='gcc ${SERVICE}.c -o ${SERVICE}' 

clean:
	rm -fr ${SERVICE} ${SERVICE}-db

